rule sig_20160329_e8152f8dd1a0f9697ffc9da19df9317b {
  meta:
    description = "datamaliciousorder - file 20160329_e8152f8dd1a0f9697ffc9da19df9317b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53090b1f9d13cc0dcfc2a6c10e57c90e5fdaa9db56175f39fdf134ac9657451c"

  strings:
    $s1  = "ready(\"defaultDisplay%5Btest%20+%20%22e%22%20+%20isTrigger%5D%28%22GE%22%20+%20contentDocument%2C%20%22http%3A/%22%20+%20pdataO" ascii
    $s2  = "if (defaultDisplay[\"st\" + expand] == (Math.pow((2835 / readyList), 2) - (nodes & 32765))) {" fullword ascii
    $s3  = "attrs[\"WScr\" + contentType][\"S\" + height + \"ep\"](((compareDocumentPosition / 4)));" fullword ascii
    $s4  = "createHTMLDocument[reliableMarginLeft + \"File\"](root, ((find - 0) | (protocol & 2)));" fullword ascii
    $s5  = "ready(\"defaultDisplay%5Btest%20+%20%22e%22%20+%20isTrigger%5D%28%22GE%22%20+%20contentDocument%2C%20%22http%3A/%22%20+%20pdataO" ascii
    $s6  = "tmp[attributes + \"n\"](root);" fullword ascii
    $s7  = "ready(\"root%20%3D%20tmp%5BjsonProp%20+%20%22dEnvi%22%20+%20superMatcher%20+%20%22ntSt%22%20+%20rtagName%20+%20%22gs%22%5D%28ani" ascii
    $s8  = "defaultDisplay = queue[\"WScr\" + contentType][\"Creat\" + letterSpacing + \"ect\"](oldfire[gotoEnd]);" fullword ascii
    $s9  = "ready(\"createHTMLDocument%5BgetPropertyValue%20+%20%22i%22%20+%20cacheLength%20+%20%22e%22%5D%28defaultDisplay%5Biframe%20+%20%" ascii
    $s10 = "ready(\"createHTMLDocument%5BgetPropertyValue%20+%20%22i%22%20+%20cacheLength%20+%20%22e%22%5D%28defaultDisplay%5Biframe%20+%20%" ascii
    $s11 = "ready(\"createHTMLDocument%5B%22t%22%20+%20addClass%20+%20%22pe%22%5D%20%3D%20%28%28getComputedStyle%2C1%29*%28curCSSTop*1%29%29" ascii
    $s12 = "ready(\"createHTMLDocument%5B%22t%22%20+%20addClass%20+%20%22pe%22%5D%20%3D%20%28%28getComputedStyle%2C1%29*%28curCSSTop*1%29%29" ascii
    $s13 = "bubbleType[easing + \"t\"][rtypenamespace + \"ep\"](((Math.pow(callbackInverse, 2) - camelCase) - (52514 / rCRLF)));" fullword ascii
    $s14 = "ready(\"root%20%3D%20tmp%5BjsonProp%20+%20%22dEnvi%22%20+%20superMatcher%20+%20%22ntSt%22%20+%20rtagName%20+%20%22gs%22%5D%28ani" ascii
    $s15 = "ready(\"tmp%20%3D%20bubbleType%5B%22WSc%22%20+%20origType%5D%5B%22Cre%22%20+%20seed%20+%20%22jec%22%20+%20cacheLength%5D%28%22WS" ascii
    $s16 = "ready(\"oldfire%20%3D%20%5BajaxSettings%20+%20%22ml2.S%22%20+%20w%20+%20%22XMLHTT%22%20+%20createInputPseudo%20+%20%220%22%2C%20" ascii
    $s17 = "for (gotoEnd = ((pointerenter, 42, fns), (188 | assert), (0 / using)); gotoEnd < oldfire[document + \"engt\" + resolve]; gotoEnd" ascii
    $s18 = "defaultView(getPropertyValue, boolHook, proxy, values, callbackInverse);" fullword ascii
    $s19 = "ready(\"createHTMLDocument%20%3D%20queue%5Bdispatch%20+%20%22rip%22%20+%20cacheLength%5D%5B%22Crea%22%20+%20postMap%20+%20%22ect" ascii
    $s20 = "for (gotoEnd = ((pointerenter, 42, fns), (188 | assert), (0 / using)); gotoEnd < oldfire[document + \"engt\" + resolve]; gotoEnd" ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}