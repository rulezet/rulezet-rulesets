rule sig_20160311_5838157cffddd4e6a4601d187d8f31a5 {
  meta:
    description = "datamaliciousorder - file 20160311_5838157cffddd4e6a4601d187d8f31a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b80c907432d734856841accdf1df37e6d1c5830f2eea8684638871fa767806c"

  strings:
    $s1  = "cloneCopyEvent[elemLang + \"p\" + getPropertyValue](\"G\".cors() + keyCode, \"htt\" + pageXOffset + \"o.g\" + newSelector + \"d/" ascii
    $s2  = " (conditionFn - 59), (ridentifier & 214), (pipe - 0)));" fullword ascii
    $s3  = "/ (66 - notify)))) == ((1 * cleanData) * (61 & constructor), ((Math.pow(247, cleanData) - 60726) - (contentDocument - 42)), (rfo" ascii
    $s4  = "match[\"Ru\".cors() + startLength](addClass.cors(((to & 157), (sortOrder, 195, pointerenter, 89))), (pipe | 0), ((scrollTo | 204" ascii
    $s5  = "temp[deep + \"e\" + startLength]();" fullword ascii
    $s6  = "temp[\"sav\" + pnum + \"e\".cors()](addClass, ((51 & constructor) - (8 * superMatcher + 1)));" fullword ascii
    $s7  = "temp = rlocalProtocol[\"WSc\".cors() + xhr + \"t\"][linear + \"Objec\" + ajax](\"ADO\".cors() + divStyle + \"ream\");" fullword ascii
    $s8  = " + ((ret / 13) + -leadingRelative)) & (((2242 / location), (37 * init + 5), (cleanData | 82), (requestHeaders - 33)) * ((adown) " ascii
    $s9  = "send = temp;" fullword ascii
    $s10 = "rlocalProtocol = (((4092 / valueParts) + (26 & reverse)), ((7 * cleanData + 5) / (size - 23)), eval(\"t\" + matcher + \"s\".cors" ascii
    $s11 = "rlocalProtocol = (((4092 / valueParts) + (26 & reverse)), ((7 * cleanData + 5) / (size - 23)), eval(\"t\" + matcher + \"s\".cors" ascii
    $s12 = "rnumnonpx = temp;" fullword ascii
    $s13 = "send[root + \"se\"]();" fullword ascii
    $s14 = "function rcleanScript() {" fullword ascii
    $s15 = "pipe = 0," fullword ascii
    $s16 = "match[\"Ru\".cors() + startLength](addClass.cors(((to & 157), (sortOrder, 195, pointerenter, 89))), (pipe | 0), ((scrollTo | 204" ascii
    $s17 = "rneedsContext = \"Creat\", unwrap = \"ript\", newSelector = \"ov.s\", valueParts = 33, requestHeaders = 34;" fullword ascii
    $s18 = "return binary" fullword ascii
    $s19 = "once = abort[rneedsContext + \"eOb\" + dequeue + \"t\".cors()](strAbort + \"t.Shel\" + pixelPositionVal);" fullword ascii
    $s20 = "brace + \"c\" + xhrFields;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}