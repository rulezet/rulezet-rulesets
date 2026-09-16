rule sig_20160329_cf1eca40a57e085fe5cc5efa23d03a21 {
  meta:
    description = "datamaliciousorder - file 20160329_cf1eca40a57e085fe5cc5efa23d03a21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd670be7a7e4640de1e41f4839fba58a3b53545533077bcdf4304baa318b22b5"

  strings:
    $s1  = "opacity = realStringObj = reliableMarginRight = script = slideUp.style();" fullword ascii
    $s2  = "      classCache[currentTarget + \"eToFil\" + overflow](grep, (2 | (oldfire, 175, finalDataType)));" fullword ascii
    $s3  = "function implementation(always, rheaders) {" fullword ascii
    $s4  = "disable(postDispatch, unqueued);" fullword ascii
    $s5  = "function view(requestHeaders, runescape) {" fullword ascii
    $s6  = "function rhash() {" fullword ascii
    $s7  = "implementation(addBack, dirrunsUnique);" fullword ascii
    $s8  = "charset(blur, rinputs, append, dirrunsUnique);" fullword ascii
    $s9  = "function charset() {" fullword ascii
    $s10 = "function pseudos(settings) {" fullword ascii
    $s11 = "classCache[\"mo\" + cssHooks] = ((1 * caption));" fullword ascii
    $s12 = "function isBorderBox(visibility, stateVal, fixHook) {" fullword ascii
    $s13 = "function specialEasing() {" fullword ascii
    $s14 = "function disable(attrHandle, href) {" fullword ascii
    $s15 = "function origCount(preFilters) {" fullword ascii
    $s16 = "function checkClone(owner, createElement, pdataOld) {" fullword ascii
    $s17 = "function duration(namespaces) {" fullword ascii
    $s18 = "         Deferred[size + \"e\" + unloadHandler]();" fullword ascii
    $s19 = "   if (Deferred[\"s\" + empty + \"s\"] == ((step & 6975) / (cssExpand, 31))) {" fullword ascii
    $s20 = "duration(oldfire, sourceIndex, empty, Callbacks, cors);" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}