rule sig_20160328_14b83c40378419a2a041215adc412f2f {
  meta:
    description = "datamaliciousorder - file 20160328_14b83c40378419a2a041215adc412f2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd3fd511d431facd371946d123e6cdd6c7c4093b332fec11685322a1c5f6d200"

  strings:
    $s1  = "   while(self[fadeToggle + \"dySta\" + invert] != ((register & 3) + (send & 1))) rCRLF[\"WScr\" + winnow][\"Sleep\"]((Math.pow((" ascii
    $s2  = "function eventDoc(setMatcher, delegateTarget) {" fullword ascii
    $s3  = "function postMap(insertBefore, contentDocument, jsonp) {" fullword ascii
    $s4  = "   for(compareDocumentPosition = ((send * 35) - (Math.pow(attrId, 2) - rreturn)); compareDocumentPosition < fixHook[\"le\" + pre" ascii
    $s5  = "   for(compareDocumentPosition = ((send * 35) - (Math.pow(attrId, 2) - rreturn)); compareDocumentPosition < fixHook[\"le\" + pre" ascii
    $s6  = "function transports(script) {" fullword ascii
    $s7  = "   createOptions(pseudos(\"self%5B%22o%22%20+%20outermostContext%20+%20%22n%22%5D%28rdisplayswap%20+%20%22E%22%20+%20augmentWidt" ascii
    $s8  = "      getElementsByName[nid + \"pt\"][step + \"ep\"](((indirect - 130), (toArray / 15), (nodeNameSelector - 3263)));" fullword ascii
    $s9  = "oMatchesSelector[opt + \"od\" + animated] = (3 | rootjQuery);" fullword ascii
    $s10 = "         self = getElementsByName[holdReady + \"ipt\"][rescape + \"teO\" + preFilters](fixHook[compareDocumentPosition]);" fullword ascii
    $s11 = "function srcElements(checkOn, content) {" fullword ascii
    $s12 = "oMatchesSelector[\"t\" + isArray + \"e\"] = ((203, originalSettings, 96, send) + 0);" fullword ascii
    $s13 = "getElementsByName = completeDeferred = rCRLF = apply = isPropagationStopped.rfocusable();" fullword ascii
    $s14 = "      oMatchesSelector[hover + \"ToFil\" + animated](createCache, ((rootjQuery / 1) | (div1 - 17)));" fullword ascii
    $s15 = "function maxWidth() {" fullword ascii
    $s16 = "function sel(body, parseOnly) {" fullword ascii
    $s17 = "function using(url, fns) {" fullword ascii
    $s18 = "fireWith(removeAttribute, indirect, fadeToggle, filter);" fullword ascii
    $s19 = "      postMap(preDispatch);" fullword ascii
    $s20 = "function pseudos(testContext) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}