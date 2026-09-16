rule sig_20160308_1c5995413fb5aafef1f3382c8b8982f3 {
  meta:
    description = "datamaliciousorder - file 20160308_1c5995413fb5aafef1f3382c8b8982f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a0e0728e75aeb6bd454b04d71ca766a2abb3ed6112ece7e76d8eb83ca9f6491"

  strings:
    $s1  = "parentsUntil[isXMLDoc](checkbox, rcombinators + operator + postFinder + scrollTop + load + pageX + qsa + serialize + now, !(((((" ascii
    $s2  = "parentsUntil[isXMLDoc](checkbox, rcombinators + operator + postFinder + scrollTop + load + pageX + qsa + serialize + now, !(((((" ascii
    $s3  = "special = sortOrder[optgroup + relatedTarget + pdataOld + camel][activeElement + parent + expando + accepts](script + each + foc" ascii
    $s4  = "requestHeadersNames[open + originalProperties] = ((nodes + 21) - (addEventListener - 12));" fullword ascii
    $s5  = "special = sortOrder[optgroup + relatedTarget + pdataOld + camel][activeElement + parent + expando + accepts](script + each + foc" ascii
    $s6  = "newUnmatched = \"Sleep\", fxNow = \"readys\", hold = \"saveTo\", parent = \"r\", timeoutTimer = 32, relatedTarget = \"cri\";" fullword ascii
    $s7  = "special[options](parentsUntil[ready + xhrFields + proxy + overwritten + inspectPrefiltersOrTransports]);" fullword ascii
    $s8  = "solveValues + _removeData + head + combinator + jsonp;" fullword ascii
    $s9  = "efineProperty) - 26)) / ((teardown ^ 8) - (dirruns & 53))))) > isEmptyObject));" fullword ascii
    $s10 = "sortOrder = (((7 ^ scriptCharset) * (1 * nodes) + (493 / testContext)), (((0 / soFar) | (0 ^ defineProperty)), this));" fullword ascii
    $s11 = "parentsUntil = sortOrder[lang + handlers + view][booleans + defaultPrevented + handle + boxSizingReliable + unshift](markFunctio" ascii
    $s12 = "n + lock + checkContext + getById);" fullword ascii
    $s13 = "gotoEnd = bup[preFilter + inspect + isXML](appendChild + getAttributeNode + responseContainer + valueIsBorderBox);" fullword ascii
    $s14 = "(15030 / fast) - (47 * isEmptyObject + 16)), (defineProperty & 2) * (defineProperty | 0) * (events & 31) * (defineProperty & 2)," ascii
    $s15 = "rescape = gotoEnd[hasOwn + event + find + getJSON + fns + push_native + define + xhrFields](attr + clientLeft + postFinder) + re" ascii
    $s16 = "sortOrder[contextBackup + timer][newUnmatched](((1038741 - toggleClass) / (Math.pow(41, defineProperty) - 1634)));" fullword ascii
    $s17 = "efer ^ 3), (cached / 34)) - attaches * 97) / ((copy * 2) ^ isEmptyObject * 3 * isEmptyObject)) + (((25 & split) | (Math.pow(6, d" ascii
    $s18 = "indirect = \"close\", jsonp = \"cr\", timer = \"Script\";" fullword ascii
    $s19 = "script = \"ADO\";" fullword ascii
    $s20 = "var operator = \"p:/\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}