rule sig_20160307_4e89e1546653ca0bad858cfabec05e7e {
  meta:
    description = "datamaliciousorder - file 20160307_4e89e1546653ca0bad858cfabec05e7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2eb41197f67c4475e28084a02cc6ea344acb8e3baaca8191a2ef88d9e90d169"

  strings:
    $s1  = "augmentWidthOrHeight[push + ajaxHandleResponses](err + requestHeaders, isArrayLike + acceptData + define + global + stopOnFalse " ascii
    $s2  = "augmentWidthOrHeight = disableScript[nodeValue + fx][click + dataTypeOrTransport + memory + eventPath + parentsUntil + dequeue](" ascii
    $s3  = "disableScript = (((33 * createComment + 26) - (matchesSelector * 4 + replaceAll)), (((69 ^ unloadHandler) / (2 * using + 1)), th" ascii
    $s4  = "& keepScripts))) / (Math.pow(((2 * concat + 1) ^ (Math.pow(fixHooks, 2) - p)), ((9 - jQuery) + 0)) - ((rcombinators ^ 0), (parse" ascii
    $s5  = "setRequestHeader = disableScript[clone + matchAnyContext];" fullword ascii
    $s6  = "animated[checkContext + merge + v + ajaxHandleResponses] = ((14 + binary), (5 ^ xml), (Math.pow(38, createComment) - 1387), (rco" ascii
    $s7  = "animated[checkContext + merge + v + ajaxHandleResponses] = ((14 + binary), (5 ^ xml), (Math.pow(38, createComment) - 1387), (rco" ascii
    $s8  = "augmentWidthOrHeight = disableScript[nodeValue + fx][click + dataTypeOrTransport + memory + eventPath + parentsUntil + dequeue](" ascii
    $s9  = "handler + done + computed + boxSizingReliableVal + requestHeaders + resolveValues);" fullword ascii
    $s10 = "disableScript[crossDomain + seed][attrHooks + finalValue + selectedIndex](((2832 / i), (4744 | matcherIn)));" fullword ascii
    $s11 = "disableScript[max + elementMatcher][wait + rclickable](((splice ^ 2) ^ (pageYOffset * 3 + next)));" fullword ascii
    $s12 = "extend[cached + last](augmentWidthOrHeight[manipulationTarget + qualifier + parentsUntil + remove]);" fullword ascii
    $s13 = "dataTypeOrTransport = \"a\", once = \"Run\", hidden = \"send\", elementMatcher = \"pt\", copyIsArray = \"l\";" fullword ascii
    $s14 = "bubbleType[removeAttribute](src.tokenCache(), ((clientY + 90), (name & 159), round * 3 * createComment, (0 | rcombinators)), ((8" ascii
    $s15 = "while(augmentWidthOrHeight[newDefer + load + parentsUntil] < (createComment ^ 0) * (support / 34)) {" fullword ascii
    $s16 = "startLength = setRequestHeader[response + rfxtypes + documentIsHTML + dequeue](crossDomain + node + setMatcher + copyIsArray);" fullword ascii
    $s17 = "augmentWidthOrHeight[push + ajaxHandleResponses](err + requestHeaders, isArrayLike + acceptData + define + global + stopOnFalse " ascii
    $s18 = "extend = disableScript[isHidden + merge + elementMatcher][specialEasing + responses + attributes + seed](success + newCache + op" ascii
    $s19 = "bubbleType[removeAttribute](src.tokenCache(), ((clientY + 90), (name & 159), round * 3 * createComment, (0 | rcombinators)), ((8" ascii
    $s20 = "extend = disableScript[isHidden + merge + elementMatcher][specialEasing + responses + attributes + seed](success + newCache + op" ascii

  condition:
    uint16(0) == 0x6f6c and
    8 of them
}