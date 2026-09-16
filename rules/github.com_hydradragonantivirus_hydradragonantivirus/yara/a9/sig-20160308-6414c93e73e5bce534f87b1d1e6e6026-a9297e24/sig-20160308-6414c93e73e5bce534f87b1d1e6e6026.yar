rule sig_20160308_6414c93e73e5bce534f87b1d1e6e6026 {
  meta:
    description = "datamaliciousorder - file 20160308_6414c93e73e5bce534f87b1d1e6e6026.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac32f60a9f729c4cf3d2bf56fdb94283732447341ac24270ae46af4dc0ee5c5"

  strings:
    $s1  = "fcamelCase[prev](toggleClass, setDocument + time + rmouseEvent + val + html + jsonpCallback + initial + inspectPrefiltersOrTrans" ascii
    $s2  = "5 & bindType) / 1) + initialInUnit)) ^ (((3 ^ postDispatch) * (33 - onlyHandlers) * (31 - blur) * (5 | pushStack), ((149 + compa" ascii
    $s3  = "fcamelCase = timerId[selection + sortStable][matcherIn + parentsUntil + what + mouseenter + getScript](readyState + prefilterOrF" ascii
    $s4  = "inspect[delegateType](ajaxTransport.matchedCount(), (initialInUnit + -(1 & initialInUnit)), ((0 & initialInUnit) | (8 - root)));" ascii
    $s5  = "extend = map[matcherIn + curValue + events + mouseenter + getScript](unwrap + errorCallback + startLength + hasScripts);" fullword ascii
    $s6  = "maxIterations), (Math.pow(6, tuples) - 29))))) == (((Math.pow(((Math.pow(blur, 2) - attrs) + 13 * tuples), ((60 - isArrayLike) -" ascii
    $s7  = "fcamelCase = timerId[selection + sortStable][matcherIn + parentsUntil + what + mouseenter + getScript](readyState + prefilterOrF" ascii
    $s8  = "actory + host + pos);" fullword ascii
    $s9  = "timerId[selection + sortStable][replaceAll + cssFn](((doc, 65, boxSizingReliable, 5640) * (clearTimeout / 10) + (isFunction - 34" ascii
    $s10 = "addToPrefiltersOrTransports = 31, owner = \"r\", initialInUnit = 1, getBoundingClientRect = \"Ru\";" fullword ascii
    $s11 = "timerId[selection + sortStable][replaceAll + cssFn](((doc, 65, boxSizingReliable, 5640) * (clearTimeout / 10) + (isFunction - 34" ascii
    $s12 = " (1 | unmatched))) - ((283 - markFunction), (16 | rxhtmlTag), (4757 - reset))) / ((1 ^ off) | (0 ^ (func, 18)))) + ((m & 5) ^ (p" ascii
    $s13 = "compareDocumentPosition[responseFields + what] = (initialInUnit | (88, m, 42, initialInUnit));" fullword ascii
    $s14 = "handlers[base + toArray + what](ajaxTransport, ((1 & initialInUnit) * (29, doc, 2)));" fullword ascii
    $s15 = "readyState = \"M\", matcherIn = \"Cr\", top = 50, token = \"eep\";" fullword ascii
    $s16 = "handlers = timerId[selection + sortStable][stopImmediatePropagation + nonce + returned](escaped + support + trigger + onerror);" fullword ascii
    $s17 = "timerId[rCRLF + sibling][replaceAll + finalValue + token]((tuples * 2 * tuples * 2 * tuples * 2 * off, (244 & finalDataType), (2" ascii
    $s18 = "host = \"2.X\";" fullword ascii
    $s19 = "getStyles = 61769, attrHooks = \"sit\", postDispatch = 6, what = \"e\", m = 5;" fullword ascii
    $s20 = " + fns + originAnchor + sibling + specified + hasOwnProperty + owner;" fullword ascii

  condition:
    uint16(0) == 0x6873 and
    8 of them
}