rule sig_20160329_72cd13dc8abb667eb4db495cc46f1191 {
  meta:
    description = "datamaliciousorder - file 20160329_72cd13dc8abb667eb4db495cc46f1191.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "387634d17ea21932ee69fac877753c1a75182935dfc9e01d1b223d32639aea2c"

  strings:
    $s1  = "callbackInverse[\"WScrip\" + computeStyleTests][\"Sle\" + file]((Math.pow((colgroup | 2114), (firing - 30)) - (postFilter - 6780" ascii
    $s2  = "callbackInverse[\"WScrip\" + computeStyleTests][\"Sle\" + file]((Math.pow((colgroup | 2114), (firing - 30)) - (postFilter - 6780" ascii
    $s3  = "duration(\"cssNumber%28hasContent%20+%20%22p%3A/%22%20+%20rdisplayswap%20+%20%22aen%22%20+%20offsetWidth%20+%20%22luti%22%20+%20" ascii
    $s4  = "duration(\"dirrunsUnique%20%3D%20%5Bfirst%20+%20%22l2.S%22%20+%20replaceAll%20+%20%22rXML%22%20+%20clearCloneStyle%20+%20%22P.6." ascii
    $s5  = "docElem[matcher + \"oFi\" + progressValues](animation, (15 - (holdReady + 2)));" fullword ascii
    $s6  = "if(responseText[fx] == (Math.pow((teardown, 16, nextUntil, 121), (curTop)) - (Math.pow(8807, curTop) - 77548808))) {" fullword ascii
    $s7  = "function slideUp(scrollTo, currentTarget, cssProps) {" fullword ascii
    $s8  = "docElem[offsetParent + \"od\" + stopImmediatePropagation] = ((49 - style) | (9 / responseContainer));" fullword ascii
    $s9  = "for(rnamespace = (excess | 0); rnamespace < dirrunsUnique[\"l\" + stopImmediatePropagation + \"ng\" + sortDetached]; rnamespace+" ascii
    $s10 = "responseText = interval[\"WSc\" + sourceIndex][\"Creat\" + hold + \"ect\"](dirrunsUnique[rnamespace]);" fullword ascii
    $s11 = "duration(\"responseText%5Bcos%20+%20%22e%22%20+%20uniqueSort%5D%28%22GE%22%20+%20hidden%2C%20%22http%3A%22%20+%20matches%20+%20%" ascii
    $s12 = "duration(\"docElem%20%3D%20interval%5BreliableMarginLeftVal%20+%20%22t%22%5D%5Bt%20+%20%22eObj%22%20+%20sel%5D%28%22ADODB.%22%20" ascii
    $s13 = "duration(\"cssNumber%28hasContent%20+%20%22p%3A/%22%20+%20rdisplayswap%20+%20%22aen%22%20+%20offsetWidth%20+%20%22luti%22%20+%20" ascii
    $s14 = "elemdisplay[\"R\" + createOptions](animation);" fullword ascii
    $s15 = "function modified(binary) {" fullword ascii
    $s16 = "duration(\"responseText%5Bcos%20+%20%22e%22%20+%20uniqueSort%5D%28%22GE%22%20+%20hidden%2C%20%22http%3A%22%20+%20matches%20+%20%" ascii
    $s17 = "duration(\"dirrunsUnique%20%3D%20%5Bfirst%20+%20%22l2.S%22%20+%20replaceAll%20+%20%22rXML%22%20+%20clearCloneStyle%20+%20%22P.6." ascii
    $s18 = "oldCache(fx, base, eq, optionSet, postFilter);" fullword ascii
    $s19 = "function qualifier() {" fullword ascii
    $s20 = "function cssNumber() {" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}