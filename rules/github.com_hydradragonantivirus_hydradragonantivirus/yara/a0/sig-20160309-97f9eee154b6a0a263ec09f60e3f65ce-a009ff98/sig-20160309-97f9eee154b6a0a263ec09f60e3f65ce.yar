rule sig_20160309_97f9eee154b6a0a263ec09f60e3f65ce {
  meta:
    description = "datamaliciousorder - file 20160309_97f9eee154b6a0a263ec09f60e3f65ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21f07131a8220e2e621270057300d8d2d79835573b633853f829f5a2b1551d13"

  strings:
    $x1  = "hasDuplicate[last + disableScript](bind, styles + elemLang + _default + fixHook + handler + key + class2type + matcherFromGroupM" ascii
    $s2  = " contents)) / ((Math.pow(10, ajaxSettings) - 88) * (ownerDocument * 3) + (Math.pow(rlocalProtocol, 2) - responseHeadersString)))" ascii
    $s3  = "hasDuplicate = elementMatchers[initial + tabIndex + pixelPositionVal][inspected + timerId + orig](headers + showHide + overrideM" ascii
    $s4  = "hasDuplicate = elementMatchers[initial + tabIndex + pixelPositionVal][inspected + timerId + orig](headers + showHide + overrideM" ascii
    $s5  = "split[fireWith + append + maxIterations](contentType, ((defer / 34), (addBack - 2)));" fullword ascii
    $s6  = "contentType = select[qsaError + qualifier + top + send + r20 + selectedIndex + idx + defaultExtra](prefilterOrFactory + copyIsAr" ascii
    $s7  = " & requestHeaders)) ^ ((166 | parseJSON) + (1 ^ addEventListener))), ((17 + (func | 124)), ((returned & 255) & (outermost, 73, r" ascii
    $s8  = "contentType = select[qsaError + qualifier + top + send + r20 + selectedIndex + idx + defaultExtra](prefilterOrFactory + copyIsAr" ascii
    $s9  = "hasDuplicate[last + disableScript](bind, styles + elemLang + _default + fixHook + handler + key + class2type + matcherFromGroupM" ascii
    $s10 = "eturned)), ((1664 ^ _) / (35 - isXMLDoc)), ((147 & tick) + (Math.pow(66, ajaxSettings) - 4242))), ((isXMLDoc ^ (Math.pow(3, ajax" ascii
    $s11 = "elementMatchers = (((157, prototype, 260) + (Math.pow(jsonpCallback, 2) - rmouseEvent)), (((252 & resolveWith) / (713 / addEvent" ascii
    $s12 = "split[last + disableScript]();" fullword ascii
    $s13 = "inspect[matcher + boxSizingReliableVal] = ((1 + -ownerDocument) ^ (29 - rclickable));" fullword ascii
    $s14 = "bind = \"GET\";" fullword ascii
    $s15 = "imeType + combinator);" fullword ascii
    $s16 = "elementMatchers = (((157, prototype, 260) + (Math.pow(jsonpCallback, 2) - rmouseEvent)), (((252 & resolveWith) / (713 / addEvent" ascii
    $s17 = "pipe = split;" fullword ascii
    $s18 = "pipe[minWidth]();" fullword ascii
    $s19 = "testContext = 34, matchers = \"Respo\", handler = \"d\", headers = \"M\", requestHeaders = 17;" fullword ascii
    $s20 = "abort = \"Creat\", responseHeadersString = 19, matcher = \"t\", outermost = 128;" fullword ascii

  condition:
    uint16(0) == 0x6261 and
    1 of ($x*) and 4 of them
}