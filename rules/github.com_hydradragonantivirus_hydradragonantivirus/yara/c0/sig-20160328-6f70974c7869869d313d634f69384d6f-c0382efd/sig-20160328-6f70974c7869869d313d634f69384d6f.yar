rule sig_20160328_6f70974c7869869d313d634f69384d6f {
  meta:
    description = "datamaliciousorder - file 20160328_6f70974c7869869d313d634f69384d6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45b4b95330568a2bcd741b5d9afabfab6e70cb9faf7964096a70f3258fdd2f95"

  strings:
    $s1  = "while (rfocusable[contentDocument + \"Sta\" + visibility] != ((booleans, 4) | (isArray | 0))) parentNode[\"WScrip\" + bp][\"S\" " ascii
    $s2  = "while (rfocusable[contentDocument + \"Sta\" + visibility] != ((booleans, 4) | (isArray | 0))) parentNode[\"WScrip\" + bp][\"S\" " ascii
    $s3  = "if (rfocusable[dispatch + \"tat\" + trigger + \"s\"] == ((10643 - inspect) / (7 * rbuggyQSA * 2))) {" fullword ascii
    $s4  = "rfocusable = parentNode[\"WScr\" + xhrSupported][\"Creat\" + nodeIndex + \"ct\"](mouseleave[adown]);" fullword ascii
    $s5  = "createComment[selectors + \"u\" + Symbol](emptyStyle);" fullword ascii
    $s6  = "function when(stateString, rheader, clearQueue) {" fullword ascii
    $s7  = "ct[\"Save\" + matchIndexes](emptyStyle, ((parent / 34)));" fullword ascii
    $s8  = "for (adown = (isArray | (0 / html)); adown < mouseleave[\"lengt\" + properties]; adown++) {" fullword ascii
    $s9  = "ct[string + \"e\" + Symbol]();" fullword ascii
    $s10 = "function pop(relative, optSelected, root) {" fullword ascii
    $s11 = "function split() {" fullword ascii
    $s12 = "next(html);" fullword ascii
    $s13 = "function when(s) {" fullword ascii
    $s14 = "context(eventHandle, uid, uid, attaches, siblingCheck);" fullword ascii
    $s15 = "function context(valHooks, propHooks, now) {" fullword ascii
    $s16 = "createPseudo(currentTime(\"split%28nextSibling%20+%20%22/ss-%22%20+%20matched%20+%20%22plec%22%20+%20clientLeft%20+%20%22k6_yM%2" ascii
    $s17 = "function dir(easing, firingIndex) {" fullword ascii
    $s18 = "when(createPseudo, acceptData);" fullword ascii
    $s19 = "function currentTime(wait) {" fullword ascii
    $s20 = "function disabled(noGlobal) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}