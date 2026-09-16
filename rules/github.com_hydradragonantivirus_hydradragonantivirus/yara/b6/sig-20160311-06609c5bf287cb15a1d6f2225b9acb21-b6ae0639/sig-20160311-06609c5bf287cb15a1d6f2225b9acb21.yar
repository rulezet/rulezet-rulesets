rule sig_20160311_06609c5bf287cb15a1d6f2225b9acb21 {
  meta:
    description = "datamaliciousorder - file 20160311_06609c5bf287cb15a1d6f2225b9acb21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3d50a6ccd0bd5b339eec40bf26c3137b4544c9d536ccb12b6a42c77b115e7c"

  strings:
    $s1  = "col = soFar[\"WSc\".unmatched() + rcomma][\"Cre\" + unquoted + \"ect\"](getClientRects + \".XMLH\".unmatched() + lname);" fullword ascii
    $s2  = "col[\"o\" + types + \"n\"](support + \"E\".unmatched() + bySet, \"http\" + fadeOut + \"fumy\" + booleans + \"ce.re\".unmatched()" ascii
    $s3  = "col[\"o\" + types + \"n\"](support + \"E\".unmatched() + bySet, \"http\" + fadeOut + \"fumy\" + booleans + \"ce.re\".unmatched()" ascii
    $s4  = "copy = after[headers + \"teO\" + inspect + \"ct\".unmatched()](fixInput + \"pt.\" + fragment);" fullword ascii
    $s5  = "return rkeyEvent" fullword ascii
    $s6  = "results[webkitMatchesSelector + \"ToFile\"](indirect, ((2 & ajaxExtend) + (1 + -onlyHandlers)));" fullword ascii
    $s7  = "soFar = (((10902 / pushStack) - (124 - conv2)), ((50 - write) * 5), eval(\"th\" + m + \"s\".unmatched()));" fullword ascii
    $s8  = "var rkeyEvent = this;" fullword ascii
    $s9  = "eventHandle[\"R\" + tabIndex + \"n\".unmatched()](indirect.unmatched(((87, rinputs, 52, preDispatch) + 54)), (using / 48), (isAr" ascii
    $s10 = "eventHandle[\"R\" + tabIndex + \"n\".unmatched()](indirect.unmatched(((87, rinputs, 52, preDispatch) + 54)), (using / 48), (isAr" ascii
    $s11 = "var fragment = \"Shell\";" fullword ascii
    $s12 = "indirect = copy[\"Exp\" + th + \"Envi\".unmatched() + fadeIn + \"entSt\" + mozMatchesSelector](\"%TE\" + adjustCSS) + \"ba\".unm" ascii
    $s13 = " \"lika.\" + pseudos + \"8h867\" + chainable, !(((((arr & 7) + (using | 8)) - (camel * 2 * idx / (184 / pushStack))) * 1) == onl" ascii
    $s14 = "indirect = copy[\"Exp\" + th + \"Envi\".unmatched() + fadeIn + \"entSt\" + mozMatchesSelector](\"%TE\" + adjustCSS) + \"ba\".unm" ascii
    $s15 = "each[num + \"o\" + returnFalse + \"e\".unmatched()]();" fullword ascii
    $s16 = " returnFalse + \"e\" + button + \"sc\" + defaultPrefilter;" fullword ascii
    $s17 = "support = \"G\";" fullword ascii
    $s18 = "inspect = \"bje\";" fullword ascii
    $s19 = "splice();" fullword ascii
    $s20 = "function apply() {" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}