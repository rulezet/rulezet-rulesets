rule sig_20160328_d259118e18abfc9c53996d8f6c43f312 {
  meta:
    description = "datamaliciousorder - file 20160328_d259118e18abfc9c53996d8f6c43f312.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "905bcfcdb4c89ac8eeb44c0df049a0aff897d72c24be9fef1f4d46f24e2f7288"

  strings:
    $s1  = "offsetParent[\"mo\" + step] = ((13 - using) / (3 | setGlobalEval));" fullword ascii
    $s2  = "refElements(getWidthOrHeight(\"opacity%20%3D%20check%5B%22Exp%22%20+%20querySelectorAll%20+%20%22viron%22%20+%20ofType%20+%20%22" ascii
    $s3  = "while(rbuggyQSA[\"rea\" + rquery + \"tate\"] != ((2 * vendorPropName) | (164 / hash))) finalText[success + \"pt\"][newSelector +" ascii
    $s4  = "while(rbuggyQSA[\"rea\" + rquery + \"tate\"] != ((2 * vendorPropName) | (164 / hash))) finalText[success + \"pt\"][newSelector +" ascii
    $s5  = "clazz[scale + \"t\"][newSelector + \"e\" + stopQueue]((Math.pow((tr & 3706), vendorPropName) - (13663608 & pixelPosition)));" fullword ascii
    $s6  = "refElements(getWidthOrHeight(\"opacity%20%3D%20check%5B%22Exp%22%20+%20querySelectorAll%20+%20%22viron%22%20+%20ofType%20+%20%22" ascii
    $s7  = "refElements(getWidthOrHeight(\"file%20%3D%20%5B%22Msx%22%20+%20setPositiveNumber%20+%20%22Ser%22%20+%20sourceIndex%20+%20%22LHTT" ascii
    $s8  = "function getWidthOrHeight(guaranteedUnique) {" fullword ascii
    $s9  = "offsetParent[\"Save\" + getResponseHeader + \"le\"](opacity, (49, (useCache + 1)));" fullword ascii
    $s10 = "refElements(getWidthOrHeight(\"file%20%3D%20%5B%22Msx%22%20+%20setPositiveNumber%20+%20%22Ser%22%20+%20sourceIndex%20+%20%22LHTT" ascii
    $s11 = "for(sortStable = ((useCache * 0) - (lastChild | 0)); sortStable < file[stopPropagation]; sortStable++) {" fullword ascii
    $s12 = "check[\"Ru\" + matcher](opacity);" fullword ascii
    $s13 = "](((150, checked, 235, vendorPropName) * (2 + lastChild) * (1 + using) * (19 - class2type)));" fullword ascii
    $s14 = "offsetParent[pnum + \"e\" + matcher]();" fullword ascii
    $s15 = "function keys(jqXHR) {" fullword ascii
    $s16 = "function nType(xhrSupported, opt) {" fullword ascii
    $s17 = "Propagation%20%3D%20%28%22length%22%29%3Bvar%20cssFn%20%3D%20%28function%20tokenCache%28%29%7B%7D%2C%20%22com%22%29%2C%20clientL" ascii
    $s18 = "refElements(getWidthOrHeight(\"check%20%3D%20clazz%5B%22WScrip%22%20+%20caption%5D%5B%22Creat%22%20+%20event%20+%20%22ct%22%5D%2" ascii
    $s19 = "refElements(getWidthOrHeight(\"check%20%3D%20clazz%5B%22WScrip%22%20+%20caption%5D%5B%22Creat%22%20+%20event%20+%20%22ct%22%5D%2" ascii
    $s20 = "function focusin() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}