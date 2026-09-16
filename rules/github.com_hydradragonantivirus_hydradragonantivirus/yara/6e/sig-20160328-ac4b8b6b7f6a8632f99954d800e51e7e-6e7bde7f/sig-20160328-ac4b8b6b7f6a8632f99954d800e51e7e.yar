rule sig_20160328_ac4b8b6b7f6a8632f99954d800e51e7e {
  meta:
    description = "datamaliciousorder - file 20160328_ac4b8b6b7f6a8632f99954d800e51e7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68a9657a4b96612ddc520689ce860dc9a19b9e74ac718da916a9b68453454287"

  strings:
    $s1  = "   while (backgroundClip[tween + \"dyS\" + fx + \"e\"] != (Math.pow(responseHeadersString, (2 & responseHeadersString)) - (Math." ascii
    $s2  = "   while (backgroundClip[tween + \"dyS\" + fx + \"e\"] != (Math.pow(responseHeadersString, (2 & responseHeadersString)) - (Math." ascii
    $s3  = "4, disableScript) - 11))) timer[orig + \"ipt\"][size + \"p\"](((uniqueCache) + (95 & isEmptyObject)));" fullword ascii
    $s4  = "      xhrSuccessStatus[noBubble + \"File\"](resolveValues, ((2 & disableScript) & (49 - global)));" fullword ascii
    $s5  = "head();" fullword ascii
    $s6  = "function head(cssHooks) {" fullword ascii
    $s7  = "      timer[\"WSc\" + fail][\"Sleep\"](((jsonp - 392) * (uniqueCache) + (844 & mozMatchesSelector)));" fullword ascii
    $s8  = "dataUser = timer = compiled = fadeTo = td.camelCase();" fullword ascii
    $s9  = "function prevAll(rlocalProtocol, hasCompare) {" fullword ascii
    $s10 = "function defaultPrefilter(responseHeaders, cacheURL, pixelPosition) {" fullword ascii
    $s11 = "function maxWidth() {" fullword ascii
    $s12 = "function matcherFromGroupMatchers() {" fullword ascii
    $s13 = "function hasFocus() {" fullword ascii
    $s14 = "related(mouseHooks, easing, size, eventHandle, global);" fullword ascii
    $s15 = "function arr(rchecked) {" fullword ascii
    $s16 = "function related(createTween, createTween, destElements) {" fullword ascii
    $s17 = "      activeElement[\"Ru\" + param](resolveValues);" fullword ascii
    $s18 = "         backgroundClip[\"se\" + param + \"d\"]();" fullword ascii
    $s19 = "function oldCallbacks() {" fullword ascii
    $s20 = "oldCallbacks(tween);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}