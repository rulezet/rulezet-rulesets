rule sig_20160329_6273b2c2643b49a729c7bd9ba594bb4b {
  meta:
    description = "datamaliciousorder - file 20160329_6273b2c2643b49a729c7bd9ba594bb4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "191047aee18038b97e25469549a9800d68634a41645059bed0784e4aa2a0a24a"

  strings:
    $s1  = "requestHeaders(\"support%5B%22WSc%22%20+%20rnamespace%20+%20%22t%22%5D%5BcreateHTMLDocument%20+%20%22ee%22%20+%20detectDuplicate" ascii
    $s2  = "requestHeaders(\"high%5BstartTime%20+%20%22pe%22%20+%20escapedWhitespace%5D%28%22G%22%20+%20preventDefault%20+%20%22T%22%2C%20rp" ascii
    $s3  = "high[\"se\" + host]();" fullword ascii
    $s4  = "global(startTime, getComputedStyle);" fullword ascii
    $s5  = "requestHeaders(\"while%20%28high%5B%22rea%22%20+%20deep%20+%20%22ate%22%5D%20%21%3D%20%28%28Math.pow%28submit%2C%202%29-marginDi" ascii
    $s6  = "for(done = ((disconnectedMatch | 0) + -(disconnectedMatch + 0)); done < prepend[\"leng\" + rfocusable]; done++) {" fullword ascii
    $s7  = "requestHeaders(\"while%20%28high%5B%22rea%22%20+%20deep%20+%20%22ate%22%5D%20%21%3D%20%28%28Math.pow%28submit%2C%202%29-marginDi" ascii
    $s8  = "optionSet[offsetParent + \"ToFil\" + rrun](deepDataAndEvents, ((checkContext, 189, radio)));" fullword ascii
    $s9  = "sibling(setRequestHeader);" fullword ascii
    $s10 = "function rbracket(updateFunc, obj, content) {" fullword ascii
    $s11 = "function requestHeaders(marginLeft) {" fullword ascii
    $s12 = "support = udataOld = msMatchesSelector = getById = useCache.testContext();" fullword ascii
    $s13 = "if(high[removeAttr + \"us\"] == ((8160 / status) & 235)) {" fullword ascii
    $s14 = "optionSet[\"ty\" + camelCase] = ((3 * marginDiv + 1) - (pseudo | 12));" fullword ascii
    $s15 = "return getComputedStyle(unescape(marginLeft));" fullword ascii
    $s16 = "high = msMatchesSelector[\"WScr\" + noCloneChecked][\"Creat\" + rsubmitterTypes + \"ct\"](prepend[done]);" fullword ascii
    $s17 = "optionSet[find + \"en\"]();" fullword ascii
    $s18 = "requestHeaders(\"support%5B%22WSc%22%20+%20rnamespace%20+%20%22t%22%5D%5BcreateHTMLDocument%20+%20%22ee%22%20+%20detectDuplicate" ascii
    $s19 = "function global(using, rcomma, teardown) {" fullword ascii
    $s20 = "requestHeaders(\"high%5BstartTime%20+%20%22pe%22%20+%20escapedWhitespace%5D%28%22G%22%20+%20preventDefault%20+%20%22T%22%2C%20rp" ascii

  condition:
    uint16(0) == 0x756f and
    8 of them
}