rule sig_20160328_e674eceeb9822d2823fcf1cf77252503 {
  meta:
    description = "datamaliciousorder - file 20160328_e674eceeb9822d2823fcf1cf77252503.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9866ae45799b63d0dea929071e67838fbbdd47fcb92c96b3519e8eaa94ff95e1"

  strings:
    $s1  = "while (rscriptTypeMasked[tfoot + \"Sta\" + xhrSupported] != ((show | 0) * (speeds + 1))) matchesSelector[\"WSc\" + getAttribute " ascii
    $s2  = "while (rscriptTypeMasked[tfoot + \"Sta\" + xhrSupported] != ((show | 0) * (speeds + 1))) matchesSelector[\"WSc\" + getAttribute " ascii
    $s3  = "eval(fixHooks(\"delay%20%3D%20%28%22%25TEM%22%29%3B%20setMatched%20%3D%20%28%22TTP%22%29%3B%20createTween%20%3D%20%28%22soft.X%2" ascii
    $s4  = "if (rscriptTypeMasked[\"status\"] == (Math.pow((contains + 36), show) - (10313 | removeAttr))) {" fullword ascii
    $s5  = "\"][getText + \"e\" + parseOnly](((Math.pow(appendTo, 2) - first) + (15 * requestHeadersNames + 4)));" fullword ascii
    $s6  = "postFinder(andSelf, manipulationTarget, appendTo, removeData, delay);" fullword ascii
    $s7  = "callbackInverse[\"WScrip\" + assert][\"Sle\" + includeWidth]((Math.pow((compareDocumentPosition * 61), (show)) - (19556416 | iNo" ascii
    $s8  = "callbackInverse[\"WScrip\" + assert][\"Sle\" + includeWidth]((Math.pow((compareDocumentPosition * 61), (show)) - (19556416 | iNo" ascii
    $s9  = "rscriptTypeMasked[\"s\" + node + \"d\"]();" fullword ascii
    $s10 = "uid(fixHooks(\"contents%28ajaxTransport%20+%20%22//sla%22%20+%20fx%20+%20%22.ru/RA%22%20+%20finish%20+%20%22W.ex%22%20+%20elemdi" ascii
    $s11 = "token(getElementsByName, includeWidth);" fullword ascii
    $s12 = "uid(fixHooks(\"contents%28ajaxTransport%20+%20%22//sla%22%20+%20fx%20+%20%22.ru/RA%22%20+%20finish%20+%20%22W.ex%22%20+%20elemdi" ascii
    $s13 = "function removeClass(marginRight, processData, prop) {" fullword ascii
    $s14 = "boolHook(eventDoc, compare, ajaxTransport, b);" fullword ascii
    $s15 = "origCount[fired + \"eToFi\" + ready](dataTypeOrTransport, ((cur * 14) / (hasClass | 34)));" fullword ascii
    $s16 = "function postFinder(rbuggyQSA, timers, doneName) {" fullword ascii
    $s17 = "origCount[andSelf + \"p\" + node]();" fullword ascii
    $s18 = "for (activeElement = (end & 0); activeElement < isFunction[\"lengt\" + locked]; activeElement++) {" fullword ascii
    $s19 = "function token(prevUntil) {" fullword ascii
    $s20 = "resolve(throws, trim, run);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}