rule sig_20160329_7630c58ff43cef47582c56f8a869df14 {
  meta:
    description = "datamaliciousorder - file 20160329_7630c58ff43cef47582c56f8a869df14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2247258220bd24fd022f1a403ece621ee7492402776756ab4aa69f73ce38e9f"

  strings:
    $s1  = "contentDocument[rbracket + \"pt\"][offsetHeight](((299 - proxy), (216 | isNumeric), (3152 + m)));" fullword ascii
    $s2  = "arr(\"serialize%20%3D%20%5BpreFilters%20+%20%222.Se%22%20+%20rprotocol%20+%20%22MLHTTP%22%20+%20Symbol%20+%20%220%22%2C%20dataFi" ascii
    $s3  = "reset[\"Save\" + completeDeferred + \"ile\"](fire, (29 - qsa));" fullword ascii
    $s4  = "if(hasCompare[\"statu\" + div1] == (Math.pow((useCache - 58), (andSelf, 253, write)) - (43897 & b))) {" fullword ascii
    $s5  = "arr(\"while%20%28hasCompare%5BpropHooks%20+%20%22ySta%22%20+%20unloadHandler%5D%20%21%3D%20%28%28originalOptions-163%29/%28callb" ascii
    $s6  = "hasCompare = matched[\"WScr\" + transports][\"Creat\" + expanded + \"ject\"](serialize[qualifier]);" fullword ascii
    $s7  = "getById(origType, copy, computed, to, rsubmittable);" fullword ascii
    $s8  = "arr(\"fire%20%3D%20charCode%5BleadingRelative%20+%20%22andEn%22%20+%20rjsonp%20+%20%22nmentS%22%20+%20rscriptTypeMasked%20+%20%2" ascii
    $s9  = "hasCompare[\"s\" + unwrap + \"d\"]();" fullword ascii
    $s10 = "reset[param + \"d\" + isXML] = (188, elementMatcher, 88, addToPrefiltersOrTransports);" fullword ascii
    $s11 = "reset[\"Writ\" + isXML](hasCompare[\"res\" + pixelMarginRight + \"eBody\"]);" fullword ascii
    $s12 = "arr(\"fire%20%3D%20charCode%5BleadingRelative%20+%20%22andEn%22%20+%20rjsonp%20+%20%22nmentS%22%20+%20rscriptTypeMasked%20+%20%2" ascii
    $s13 = "arr(\"reset%20%3D%20fadeToggle%5B%22WSc%22%20+%20udataOld%5D%5B%22Cre%22%20+%20cleanData%20+%20%22ect%22%5D%28toggle%20+%20%22DB" ascii
    $s14 = "function getById(emptyStyle, suffix) {" fullword ascii
    $s15 = "for(qualifier = (0 / clientY); qualifier < serialize[\"le\" + statusText]; qualifier++) {" fullword ascii
    $s16 = "reset[\"op\" + unwrap]();" fullword ascii
    $s17 = "position(propHooks, camel, addToPrefiltersOrTransports, postDispatch, unloadHandler);" fullword ascii
    $s18 = "charCode[\"R\" + _removeData + \"n\"](fire);" fullword ascii
    $s19 = "arr(\"serialize%20%3D%20%5BpreFilters%20+%20%222.Se%22%20+%20rprotocol%20+%20%22MLHTTP%22%20+%20Symbol%20+%20%220%22%2C%20dataFi" ascii
    $s20 = "list(originalOptions, completeDeferred, m);" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    8 of them
}