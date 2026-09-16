rule sig_20160329_a130f005f25f2e2f0989e01c0f932654 {
  meta:
    description = "datamaliciousorder - file 20160329_a130f005f25f2e2f0989e01c0f932654.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3279b685f05454b96429cb330df3ed8d07feb5c430148a8485456d387b92e3c8"

  strings:
    $s1  = "matcherFromTokens(\"while%20%28rbuggyMatches%5B%22read%22%20+%20prevUntil%20+%20%22te%22%5D%20%21%3D%20%28%2830%2CnoConflict%29%" ascii
    $s2  = "rbuggyMatches = before[inPage + \"pt\"][dataTypeOrTransport + \"ateOb\" + getWidthOrHeight](nid[support]);" fullword ascii
    $s3  = "for (support = ((safeActiveElement | 0) / (source - 59)); support < nid[guid + \"h\"]; support++) {" fullword ascii
    $s4  = "args[\"m\" + lang + \"de\"] = (22 - define);" fullword ascii
    $s5  = "matcherFromTokens(\"while%20%28rbuggyMatches%5B%22read%22%20+%20prevUntil%20+%20%22te%22%5D%20%21%3D%20%28%2830%2CnoConflict%29%" ascii
    $s6  = "contentType[selected + \"n\"](callback);" fullword ascii
    $s7  = "function valHooks(host, hidden) {" fullword ascii
    $s8  = "mouseHooks(getter, returnTrue, lname, propFilter);" fullword ascii
    $s9  = "args[\"SaveT\" + parse + \"e\"](callback, ((24 + _queueHooks) - (39 & namespace)));" fullword ascii
    $s10 = "progressContexts(rootjQuery, resolveValues, createInputPseudo, setMatchers, define);" fullword ascii
    $s11 = "function matcherFromTokens(newUnmatched) {" fullword ascii
    $s12 = "function props(ready) {" fullword ascii
    $s13 = "rCRLF(implicitRelative, getElementsByName, selection);" fullword ascii
    $s14 = "function progressContexts() {" fullword ascii
    $s15 = "function msg() {" fullword ascii
    $s16 = "function elemData() {" fullword ascii
    $s17 = "function mouseHooks(remaining, deep, factory) {" fullword ascii
    $s18 = "function matcher(globalEval) {" fullword ascii
    $s19 = "attrNames = opener = before = tbody = div.animate();" fullword ascii
    $s20 = "function delay(id, soFar) {" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}