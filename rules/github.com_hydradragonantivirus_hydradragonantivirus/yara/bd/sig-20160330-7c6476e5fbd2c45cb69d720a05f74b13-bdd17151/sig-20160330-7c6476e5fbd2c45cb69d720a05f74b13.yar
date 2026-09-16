rule sig_20160330_7c6476e5fbd2c45cb69d720a05f74b13 {
  meta:
    description = "datamaliciousorder - file 20160330_7c6476e5fbd2c45cb69d720a05f74b13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e30ddfee3e5a4e282eb3e3f3cbcd6597fac8a7e0a804b6ad5a92a058fcf90383"

  strings:
    $x1  = "eval(unescape([\"win&20&3D&20&28&22se&22&29&3Bvar&20lock&20&3D&20&28&22t.XML&22&29&3Bclasses&20&3D&20&28&22t.S&22&29&\", \"2C&20" ascii
    $s2  = "fire[buildParams + \"p\" + subtract] = ((74 - detach) - (120, processData, 46));" fullword ascii
    $s3  = "    test(\"curCSSTop&20&3D&20&5BgetWindow&20+&20&222.Ser&22&20+&20results&20+&20&22MLH&22&20+&20responseContainer&20+&20&22.0&22" ascii
    $s4  = "function targets() {" fullword ascii
    $s5  = "target(isDefaultPrevented);" fullword ascii
    $s6  = "function target(pageXOffset, valHooks) {" fullword ascii
    $s7  = "    test(\"getById&20&3D&20matcherFromTokens&5BisImmediatePropagationStopped&20+&20&22dEnvi&22&20+&20siblingCheck&20+&20&22tStri" ascii
    $s8  = "        b[top + \"pt\"][idx](((Math.pow(2660, window) - 7070728) | (ajaxTransport | 640)));" fullword ascii
    $s9  = "function removeEventListener(hasScripts, rnative) {" fullword ascii
    $s10 = "hide(responseText, sortStable, rscriptTypeMasked);" fullword ascii
    $s11 = "script = 186;" fullword ascii
    $s12 = "    test(\"targets&28&22htt&22&20+&20random&20+&20&22amsoc&22&20+&20rbuggyMatches&20+&20&22isinh.&22&20+&20createPseudo&20+&20&2" ascii
    $s13 = "    if(special[rrun + \"atus\"] == ((version * 2 * window * 5 * window))) {" fullword ascii
    $s14 = "    test(\"targets&28&22htt&22&20+&20random&20+&20&22amsoc&22&20+&20rbuggyMatches&20+&20&22isinh.&22&20+&20createPseudo&20+&20&2" ascii
    $s15 = "fire[\"m\" + makeArray + \"e\"] = ((2 + reset));" fullword ascii
    $s16 = "        fire[\"SaveT\" + backgroundClip + \"e\"](getById, ((38, window) & (1 * matches)));" fullword ascii
    $s17 = "*version*2*window*2*version*2&29/&28matches*5+reset&29&29&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s18 = "    test(\"getById&20&3D&20matcherFromTokens&5BisImmediatePropagationStopped&20+&20&22dEnvi&22&20+&20siblingCheck&20+&20&22tStri" ascii
    $s19 = "    test(\"curCSSTop&20&3D&20&5BgetWindow&20+&20&222.Ser&22&20+&20results&20+&20&22MLH&22&20+&20responseContainer&20+&20&22.0&22" ascii
    $s20 = "function funcName() {" fullword ascii

  condition:
    uint16(0) == 0x6373 and
    1 of ($x*) and 4 of them
}