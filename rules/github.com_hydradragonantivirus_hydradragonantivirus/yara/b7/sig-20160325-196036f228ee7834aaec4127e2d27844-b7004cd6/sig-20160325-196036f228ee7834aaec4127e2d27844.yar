rule sig_20160325_196036f228ee7834aaec4127e2d27844 {
  meta:
    description = "datamaliciousorder - file 20160325_196036f228ee7834aaec4127e2d27844.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "215dbf58e7481ff125e103c59772ca5c5809ccc4acddc1f6c439797f16580262"

  strings:
    $s1  = "unit[operator + \"p\" + origType] = (5 * wrap * 7, (curCSS - 27), (fired - 27));" fullword ascii
    $s2  = "getAttributeNode = dataTypeOrTransport[\"Creat\" + matcher + \"ect\"](parts + \"rip\" + func + \"ell\");" fullword ascii
    $s3  = "locked[parts + \"rip\" + scrollLeft][\"Sleep\"](((dataTypeExpression / 27) / (eq * 2 + hasScripts)));" fullword ascii
    $s4  = "forward = \"pons\", complete = \"p\";" fullword ascii
    $s5  = "var timerId = [][\"cons\" + animated + \"ctor\"][rlocalProtocol + \"toty\" + requestHeadersNames][\"so\" + emptyGet + \"t\"][hov" ascii
    $s6  = "dataTypeOrTransport = locked[\"WScr\" + simple];" fullword ascii
    $s7  = "errorCallback = \"ADODB.\", compare = \"htt\", getClass = \"MP%\", func = \"t.Sh\", matcher = \"eObj\", curCSS = 74;" fullword ascii
    $s8  = "context = \"o\", hasScripts = 1, createPseudo = 20;" fullword ascii
    $s9  = "eval(serialize(\"rootjQuery%5Bcontext%20+%20%22p%22%20+%20origType%20+%20%22n%22%5D%28beforeunload%20+%20%22T%22%2C%20compare%20" ascii
    $s10 = "eval(serialize(\"expanded%5B%22posit%22%20+%20random%5D%20%3D%20%28%28hasScripts+-1%29%7CDOMParser%29%3B\"));" fullword ascii
    $s11 = "eval(serialize(\"rootjQuery%5Bcontext%20+%20%22p%22%20+%20origType%20+%20%22n%22%5D%28beforeunload%20+%20%22T%22%2C%20compare%20" ascii
    $s12 = "eval(serialize(\"ret%20%3D%20getAttributeNode%3B\"));" fullword ascii
    $s13 = "eval(serialize(\"cssText%28%22Res%22%20+%20forward%20+%20%22eBody%22%2C%20%28%28nodeValue*3%29%26%28eq+13%29%29%2C%20expanded%2C" ascii
    $s14 = "factory(beforeSend, emptyGet);" fullword ascii
    $s15 = "operator = \"ty\"," fullword ascii
    $s16 = "eval(serialize(\"cssText%28%22Res%22%20+%20forward%20+%20%22eBody%22%2C%20%28%28nodeValue*3%29%26%28eq+13%29%29%2C%20expanded%2C" ascii
    $s17 = "eval(serialize(\"unit%5B%22o%22%20+%20complete%20+%20%22en%22%5D%28%29%3B\"));" fullword ascii
    $s18 = "stopQueue = contexts = close = locked = clientLeft.transports();" fullword ascii
    $s19 = "eval(serialize(\"rootjQuery%20%3D%20new%20contexts%5Boptions%20+%20%22XObjec%22%20+%20scrollLeft%5D%28%22Msx%22%20+%20noBubble%2" ascii
    $s20 = "eval(serialize(\"rootjQuery%20%3D%20new%20contexts%5Boptions%20+%20%22XObjec%22%20+%20scrollLeft%5D%28%22Msx%22%20+%20noBubble%2" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}