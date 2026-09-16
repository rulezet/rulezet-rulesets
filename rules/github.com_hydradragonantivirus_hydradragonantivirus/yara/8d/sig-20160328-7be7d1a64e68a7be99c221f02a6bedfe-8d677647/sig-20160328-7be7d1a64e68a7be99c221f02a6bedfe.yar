rule sig_20160328_7be7d1a64e68a7be99c221f02a6bedfe {
  meta:
    description = "datamaliciousorder - file 20160328_7be7d1a64e68a7be99c221f02a6bedfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d380ae99ee893db5f00047f9f8260d9c2e6d27dbe9c64dbf3506185ff5ff4fc4"

  strings:
    $s1  = "if (fixHooks[target + \"ta\" + set + \"us\"] == (Math.pow((Math.pow(90, valHooks) - 7959), valHooks) - (Math.pow(12350, valHooks" ascii
    $s2  = "if (fixHooks[target + \"ta\" + set + \"us\"] == (Math.pow((Math.pow(90, valHooks) - 7959), valHooks) - (Math.pow(12350, valHooks" ascii
    $s3  = "ap(isArray, getComputedStyle, target, xhrSupported);" fullword ascii
    $s4  = "doc[computeStyleTests + \"Fil\" + completed](rnamespace, ((reverse | 101), (temp & 239), (writable / 9), (removeEvent & 2)));" fullword ascii
    $s5  = "function isPlainObject(delegateCount, manipulationTarget, text) {" fullword ascii
    $s6  = "copy%20%3D%20%28%22y%22%29%3BxhrSupported%20%3D%20%28%22ADO%22%29%3B%20toArray%20%3D%20%284%29%3B%20temp%20%3D%20%28162%29%3B%20" ascii
    $s7  = "callback(MAX_NEGATIVE, temp, isLocal, parse);" fullword ascii
    $s8  = "while (fixHooks[\"rea\" + source + \"tate\"] != ((106 / valHooks) - (49 | nonce))) superMatcher[funescape + \"ipt\"][parentWindo" ascii
    $s9  = "for (once = (0 & (originalEvent / 38)); once < createDocumentFragment[rinputs + \"engt\" + bp]; once++) {" fullword ascii
    $s10 = "curLeft[window + \"un\"](rnamespace);" fullword ascii
    $s11 = "doc[handleObjIn + \"te\"](fixHooks[toSelector + \"seBod\" + copy]);" fullword ascii
    $s12 = "while (fixHooks[\"rea\" + source + \"tate\"] != ((106 / valHooks) - (49 | nonce))) superMatcher[funescape + \"ipt\"][parentWindo" ascii
    $s13 = "doc[random + \"en\"]();" fullword ascii
    $s14 = "on(ajaxHandleResponses(\"superMatcher%5B%22WSc%22%20+%20MAX_NEGATIVE%5D%5B%22Sl%22%20+%20completed%20+%20%22ep%22%5D%28%28%28tim" ascii
    $s15 = "optgroup(isArray, escaped, proxy, xhrSupported);" fullword ascii
    $s16 = "function noBubble() {" fullword ascii
    $s17 = "owner(attaches, i, curCSSLeft);" fullword ascii
    $s18 = "function defaultPrefilter(createPseudo) {" fullword ascii
    $s19 = "function ajaxHandleResponses(linear) {" fullword ascii
    $s20 = "second(reverse);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}