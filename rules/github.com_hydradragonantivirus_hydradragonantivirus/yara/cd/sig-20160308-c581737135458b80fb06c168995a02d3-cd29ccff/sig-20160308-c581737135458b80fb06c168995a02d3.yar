rule sig_20160308_c581737135458b80fb06c168995a02d3 {
  meta:
    description = "datamaliciousorder - file 20160308_c581737135458b80fb06c168995a02d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16a2d0046876dfc8080de018f092fe76e439ee14a76bcb675b3067d02be5ce57"

  strings:
    $s1  = "defineProperty[resolve](pixelMarginRightVal.adjusted(), ((Math.pow(origCount, 2) - close) - (Math.pow(7, completeDeferred) - 38)" ascii
    $s2  = "defineProperty[resolve](pixelMarginRightVal.adjusted(), ((Math.pow(origCount, 2) - close) - (Math.pow(7, completeDeferred) - 38)" ascii
    $s3  = "while(i[rchecked + delegateTarget + elems] < ((54 / origCount) & (131, original))) {" fullword ascii
    $s4  = "errorCallback[stopped + namespaces][ret + globalEventContext](((Math.pow(124, completeDeferred) - 15207) - (fast, 201, setPositi" ascii
    $s5  = "errorCallback[stopped + namespaces][ret + globalEventContext](((Math.pow(124, completeDeferred) - 15207) - (fast, 201, setPositi" ascii
    $s6  = "insertAfter[arr + qualifier](i[win + getJSON + method + dirrunsUnique + container + docElem]);" fullword ascii
    $s7  = "i[hasDuplicate + val](get, base + createFxNow + checkOn + postFinder + sibling + sortInput + rreturn + stopOnFalse + rfocusable " ascii
    $s8  = "i = errorCallback[toSelector + fireWith + beforeunload][propFilter + safeActiveElement + visibility + beforeunload](tokenize + g" ascii
    $s9  = "insertBefore = \"Create\", getter = \"2.XM\", delegateTarget = \"ead\";" fullword ascii
    $s10 = "firingIndex[pageXOffset + reliableMarginLeftVal] = ((87 - checkClone) - (72 / original));" fullword ascii
    $s11 = " - 43))) | ((cssNormalTransform ^ 51) - (original * 11 + cssNormalTransform))))));" fullword ascii
    $s12 = "i = errorCallback[toSelector + fireWith + beforeunload][propFilter + safeActiveElement + visibility + beforeunload](tokenize + g" ascii
    $s13 = "errorCallback[toSelector + fireWith + beforeunload][compare + filters + fireWith](((finalText / 4) | (rneedsContext, 69, done)))" ascii
    $s14 = "errorCallback[toSelector + fireWith + beforeunload][compare + filters + fireWith](((finalText / 4) | (rneedsContext, 69, done)))" ascii
    $s15 = "unshift = camelCase[insertBefore + assert](compiled + expand + dataUser);" fullword ascii
    $s16 = "i[hasDuplicate + val](get, base + createFxNow + checkOn + postFinder + sibling + sortInput + rreturn + stopOnFalse + rfocusable " ascii
    $s17 = "resolve = win + locked;" fullword ascii
    $s18 = "pixelMarginRightVal = unshift[height + b + toggle + box + ajaxHandleResponses + speeds + _default + success](setTimeout + random" ascii
    $s19 = "pixelMarginRightVal = unshift[height + b + toggle + box + ajaxHandleResponses + speeds + _default + success](setTimeout + random" ascii
    $s20 = "etter + bySet + condense);" fullword ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}