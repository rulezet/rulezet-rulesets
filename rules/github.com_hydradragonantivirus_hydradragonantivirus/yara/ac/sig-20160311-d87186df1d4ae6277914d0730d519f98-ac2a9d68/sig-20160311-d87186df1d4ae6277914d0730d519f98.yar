rule sig_20160311_d87186df1d4ae6277914d0730d519f98 {
  meta:
    description = "datamaliciousorder - file 20160311_d87186df1d4ae6277914d0730d519f98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f59fac09df304ae28df280d89f682be8c5f90f830c925c53c4c4824a12426062"

  strings:
    $s1  = "rscriptTypeMasked[\"o\".originalSettings() + seekingTransport + \"n\"](handleObjIn + \"T\", getPropertyValue + \"://50\".origina" ascii
    $s2  = "nid = isEmptyObject[then + \"Envir\" + closest + \"entStr\".originalSettings() + combinator](\"%TEMP\" + rrun) + \"replac\" + si" ascii
    $s3  = "needsContext[high + \"un\"](nid.originalSettings(((qsaError & 1791) / (Math.pow(elementMatcher, 2) - optDisabled))), ((0 / pixel" ascii
    $s4  = "needsContext[high + \"un\"](nid.originalSettings(((qsaError & 1791) / (Math.pow(elementMatcher, 2) - optDisabled))), ((0 / pixel" ascii
    $s5  = "nid = isEmptyObject[then + \"Envir\" + closest + \"entStr\".originalSettings() + combinator](\"%TEMP\" + rrun) + \"replac\" + si" ascii
    $s6  = " 383)), ((offset | 1) + fns)) - ((Math.pow(24808, serializeArray) - 615397861) * (_$ - 23) + (dataTypeOrTransport, 47, factory, " ascii
    $s7  = "rscriptTypeMasked[support + \"en\" + delegateCount]();" fullword ascii
    $s8  = "defaultPrevented = conv[\"WSc\" + splice][\"Crea\".originalSettings() + shift + \"bject\"](remaining + \"B.Str\" + responseHeade" ascii
    $s9  = "defaultPrevented = conv[\"WSc\" + splice][\"Crea\".originalSettings() + shift + \"bject\"](remaining + \"B.Str\" + responseHeade" ascii
    $s10 = "zeArray) - 107)))), (Math.pow((((optgroup + 0) | (fns * 1)) | ((Math.pow(window, 2) - copy) & 2 * serializeArray * 31)), (((resp" ascii
    $s11 = "rscriptTypeMasked = conv[\"WScrip\" + rtagName][\"Create\".originalSettings() + func](\"MSXM\" + dataPriv + \"HTT\" + start);" fullword ascii
    $s12 = "/ pixelMarginRightVal))) * (((62 - hidden) + 0) & (fns + (0 | noGlobal))) + (((15 - eventDoc) & (7 & tbody)) & ((2 | serializeAr" ascii
    $s13 = "onses - 12), (toggle / 11), (fns | 0)) + ((isTrigger / 42) & (fns * 1)))) - ((offset | 3) * (wrap, 239, simulate, 7) * (offset |" ascii
    $s14 = "\".\".originalSettings() + support + \"c\" + preMap;" fullword ascii
    $s15 = "s() + after + \".211\" + fxNow + \"dd0/89\" + rtrim + \"6u5y4\".originalSettings(), !(2 == (((Math.pow(((chainable & 360) & (ona" ascii
    $s16 = "support = \"s\"," fullword ascii
    $s17 = "combinator = \"ings\";" fullword ascii
    $s18 = "return slow" fullword ascii
    $s19 = "function gotoEnd() {" fullword ascii
    $s20 = "function t() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}