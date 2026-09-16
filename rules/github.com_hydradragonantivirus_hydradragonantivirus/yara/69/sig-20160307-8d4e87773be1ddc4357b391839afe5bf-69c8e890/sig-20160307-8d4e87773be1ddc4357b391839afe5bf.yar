rule sig_20160307_8d4e87773be1ddc4357b391839afe5bf {
  meta:
    description = "datamaliciousorder - file 20160307_8d4e87773be1ddc4357b391839afe5bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acddef0cf31da572c7abb2c70b9679d276d164ad19ba3e25e58b3d3948109e6f"

  strings:
    $s1  = "uniqueID[isDefaultPrevented + context][timeoutTimer](((Math.pow(tokenCache, 2) - fragment) & (642222 / target)));" fullword ascii
    $s2  = "slideUp[queue + nid](compare[disabled + clazz + targets]);" fullword ascii
    $s3  = "isEmptyObject = matchAnyContext[noConflict + dataShow + swing + empty + _queueHooks + map](pixelPosition + getter + preventDefau" ascii
    $s4  = "compare[host + expanded](guaranteedUnique, matcherFromGroupMatchers + speed + onload + attaches + defaultDisplay + class2type + " ascii
    $s5  = "round[noop] = ((15 - udataOld) + (0 / postSelector));" fullword ascii
    $s6  = "until[swap + requestHeadersNames + expanded] = ((15 ^ attachEvent) - (23 & postSelector));" fullword ascii
    $s7  = "uniqueID = ((2 ^ matcher) * (164 - winnow) * (2 + matcher), ((Math.pow((17 + when), (2 | matcher)) - (556 - copyIsArray)), this)" ascii
    $s8  = "lt) + oldfire + hidden + addEventListener + progress;" fullword ascii
    $s9  = "atcher ^ 0) & (rsingleTag - 14))))) - (((when + -(1 & when)) | ((12 + fixHooks) | (7 * elementMatchers + 1))), ((Math.pow((propN" ascii
    $s10 = "uniqueID = ((2 ^ matcher) * (164 - winnow) * (2 + matcher), ((Math.pow((17 + when), (2 | matcher)) - (556 - copyIsArray)), this)" ascii
    $s11 = "target = 42;" fullword ascii
    $s12 = "isEmptyObject = matchAnyContext[noConflict + dataShow + swing + empty + _queueHooks + map](pixelPosition + getter + preventDefau" ascii
    $s13 = "slideUp[isBorderBox + td + rbuggyQSA + inspected + string](isEmptyObject, ((26 - elementMatchers) + (0 | when)));" fullword ascii
    $s14 = "compare[host + expanded](guaranteedUnique, matcherFromGroupMatchers + speed + onload + attaches + defaultDisplay + class2type + " ascii
    $s15 = "out | 17) * (curPosition ^ 9), (hasOwnProperty ^ 53), ((resolveContexts | 4360) / (prev - 67))), (((when & 0) ^ (aup & 2)) ^ ((m" ascii
    $s16 = "makeArray + newSelector + reset, !((Math.pow(((((65 + body) / (59 - duplicates)) & 7) + ((nodes / 50) - (obj - 75))), (((setTime" ascii
    $s17 = "matchAnyContext = offsetHeight[conv2 + notifyWith + markFunction](isDefaultPrevented + context + xml + username);" fullword ascii
    $s18 = "compare[extend + expand]();" fullword ascii
    $s19 = "while (compare[classes + rquickExpr + isReady] < (2 * curElem * 2 * curPosition / (8 + curPosition))) {" fullword ascii
    $s20 = "getter = \"EMP%\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}