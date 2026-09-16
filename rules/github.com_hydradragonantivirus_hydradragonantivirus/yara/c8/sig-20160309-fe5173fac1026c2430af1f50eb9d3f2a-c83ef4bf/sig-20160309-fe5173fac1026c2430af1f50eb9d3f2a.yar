rule sig_20160309_fe5173fac1026c2430af1f50eb9d3f2a {
  meta:
    description = "datamaliciousorder - file 20160309_fe5173fac1026c2430af1f50eb9d3f2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2687af0412b35c462aed5a76a71c4dcb7e96a65e012c78e603decdf27e5c55c"

  strings:
    $s1  = "head[curOffset + processData](active + isEmptyObject, callbackContext + fix + index + unqueued + next + args + _data + unquoted " ascii
    $s2  = "head = guaranteedUnique[readyState + once + getWidthOrHeight + chainable + setPositiveNumber][parseHTML + dataType + setPositive" ascii
    $s3  = " * ((((responseHeaders | 0) | (winnow * 0)) | ((winnow ^ 0) ^ (winnow * 3))) & (((winnow * 2) + attrs) - ((645 / binary) / (5 ^ " ascii
    $s4  = "head[curOffset + processData](active + isEmptyObject, callbackContext + fix + index + unqueued + next + args + _data + unquoted " ascii
    $s5  = "protocol = augmentWidthOrHeight[$ + _ + key + origFn + visible + responseType](node + pageYOffset) + soFar + groups + getRespons" ascii
    $s6  = "rbuggyMatches = head[until + createComment + all + next + matcherFromTokens + delay];" fullword ascii
    $s7  = "Number](overrideMimeType + stateString + dispatch + get + relatedTarget + fn + Data);" fullword ascii
    $s8  = "+ tfoot + eventDoc, !((((((1 * winnow) * (2 & finalText)) ^ (0 - (margin - 12))) + (((finalText / 2) ^ (responseHeaders / 27))))" ascii
    $s9  = "responseHeaders)))) + ((0 | ((b, 215), fire * 5, (implementation), (51 - isHidden))) - (((8 ^ responseHeaders) * (123 / siblings" ascii
    $s10 = "head = guaranteedUnique[readyState + once + getWidthOrHeight + chainable + setPositiveNumber][parseHTML + dataType + setPositive" ascii
    $s11 = "protocol = augmentWidthOrHeight[$ + _ + key + origFn + visible + responseType](node + pageYOffset) + soFar + groups + getRespons" ascii
    $s12 = "bubbleType = 19, winnow = 1, compareDocumentPosition = \".scr\", tfoot = \"o76g4\";" fullword ascii
    $s13 = "head[getElementById + nodeName]();" fullword ascii
    $s14 = "preMap[one](protocol.href(), ((fire - 10) * (winnow + -1)), ((bySet, 102, copy, 1) & (winnow * 0)));" fullword ascii
    $s15 = "node = \"%TEMP\";" fullword ascii
    $s16 = "augmentWidthOrHeight = addCombinator[srcElements + sortDetached + setPositiveNumber](defaultPrevented + which + marginLeft + got" ascii
    $s17 = "augmentWidthOrHeight = addCombinator[srcElements + sortDetached + setPositiveNumber](defaultPrevented + which + marginLeft + got" ascii
    $s18 = "guaranteedUnique[readyState + pageX][dataAttr](((182, button, 15100) & (rjsonp ^ 15910)));" fullword ascii
    $s19 = "qsaError[setPositiveNumber + write] = (1 * winnow);" fullword ascii
    $s20 = "top = \"File\", Data = \"P\", rscriptType = 9, fire = 11, all = \"n\";" fullword ascii

  condition:
    uint16(0) == 0x6962 and
    8 of them
}