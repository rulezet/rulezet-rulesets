rule sig_20160308_7c7674a0680665862659ffedf12c1e79 {
  meta:
    description = "datamaliciousorder - file 20160308_7c7674a0680665862659ffedf12c1e79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2088757c741c8556843e73801df1d1caf05feca72a61cece55faff8e7c15f1b"

  strings:
    $s1  = "ct = current[progressContexts + completeDeferred + rheaders + isNumeric + rparentsprev + interval + obj + mappedTypes](processDa" ascii
    $s2  = "ct = current[progressContexts + completeDeferred + rheaders + isNumeric + rparentsprev + interval + obj + mappedTypes](processDa" ascii
    $s3  = "list[ignored + scrollTop + content][children](((bind * 6 + queue) + (75, seed, 210, delegateTarget)));" fullword ascii
    $s4  = "| (when * (6 + requestHeadersNames) * (9 / when) - (120 / insertAfter))) - ((((533 ^ rfxtypes) * (Math.pow(3, dataUser) - 5) + (" ascii
    $s5  = "list[optgroup + showHide][children]((Math.pow((174, getById, 94), (preDispatch - 51)) - (originAnchor | 544)));" fullword ascii
    $s6  = " - 103), (active * 2 + cacheURL), (Math.pow(6, dataUser) - 29)), (((structure | 4) & (funcName & 63)) ^ ((getElementsByClassName" ascii
    $s7  = "pointerenter[bp + attrs](copyIsArray, rmouseEvent + createTween + isXML + fadeOut + valHooks + href + xhrFields + responseHeader" ascii
    $s8  = " ^ 1) * (requestHeadersNames & 1))), (Math.pow(((callback - 46) / (once / 46)), dataUser) - (Math.pow((7 & scale), (34 / simple)" ascii
    $s9  = "s + rcssNum + setAttribute + arg + handleObj + winnow + activeElement, !((((((Math.pow(60, dataUser) - 3508) * (when & 2) + (mou" ascii
    $s10 = "pointerenter = list[next + teardown][defaultValue + getElementsByName + host](fragment + opacity + pageY + overflow);" fullword ascii
    $s11 = "estContext)), ((0 | requestHeadersNames) + (1 * requestHeadersNames))) - ((367 + prototype) ^ 3 * sort))))));" fullword ascii
    $s12 = "0 / hooks)) + (0 | requestHeadersNames))) / ((Math.pow((19 + scale), 2) - (conditionFn / 42)) * ((getPropertyValue + 2), (append" ascii
    $s13 = "list = ((43 - rnoInnerhtml) * (2 * when + 1), (((buildFragment - 16), (Math.pow(original, 2) - lock), (5 + markFunction)), this)" ascii
    $s14 = ") - (106, prevAll))))) == (((Math.pow(((16 + offset) - (2 ^ stopped)), ((0 | collection) - (6 | wait))) - (4 ^ (cssProps | 1))) " ascii
    $s15 = "list = ((43 - rnoInnerhtml) * (2 * when + 1), (((buildFragment - 16), (Math.pow(original, 2) - lock), (5 + markFunction)), this)" ascii
    $s16 = "ta + matcherFromGroupMatchers) + username + clearInterval + dataTypeOrTransport + fast;" fullword ascii
    $s17 = "seHooks, 37, createCache)), ((Math.pow(2245, dataUser) - 5037211) - (qsa + 455))) / (when * ((69 / setMatched) * (2 & when) + (7" ascii
    $s18 = "uniqueSort = list[optgroup + showHide][computeStyleTests + createPseudo + mimeType](get + className + until + detectDuplicates +" ascii
    $s19 = "uniqueSort = list[optgroup + showHide][computeStyleTests + createPseudo + mimeType](get + className + until + detectDuplicates +" ascii
    $s20 = "fast = \".scr\";" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}