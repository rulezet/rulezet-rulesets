rule sig_20160308_214d1bdc84cc3d19a28945b946b35e80 {
  meta:
    description = "datamaliciousorder - file 20160308_214d1bdc84cc3d19a28945b946b35e80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b252d19f0fb3b9e97be2c8fc052787da591dbd37053573331fad91e7f785bdaa"

  strings:
    $s1  = "bulk = push_native[getScript + namespace + delegateCount][completeDeferred + elems + key](checkContext + completed + removeData)" ascii
    $s2  = "bulk = push_native[getScript + namespace + delegateCount][completeDeferred + elems + key](checkContext + completed + removeData)" ascii
    $s3  = "ath.pow(conv2, 2) - box), (Math.pow(158, parse) - 24795), (el ^ 1)) * ((version | 0) + -(el | 1)))) | ((((rhtml - 22) * pageXOff" ascii
    $s4  = "Expr = rprotocol[sortDetached + done + key](optSelected + maxIterations + safeActiveElement + empty + currentTarget);" fullword ascii
    $s5  = "dataAttr[mozMatchesSelector + matches + slow + isDefaultPrevented](andSelf, attributes + ifModified + expanded + valueParts + rc" ascii
    $s6  = "push_native[getScript + safeActiveElement + matcher + delegateCount][_](((addGetHookIf + 153667) / wait * 2));" fullword ascii
    $s7  = "dataAttr = push_native[optSelected + finish + createInputPseudo][curCSS + type + key](specified + rjsonp + vendorPropName + head" ascii
    $s8  = "lowX | 4)), (curPosition / 50) * (version * 2), ((list, 236, accepts) & (Math.pow(4, parse) - 11))) + (((superMatcher ^ 114), (M" ascii
    $s9  = "lass + globalEventContext + reliableMarginRight + finalValue + remove + raw + iterator + scripts, !((((((onerror & 118) | (overf" ascii
    $s10 = "fire = \"tr\", matcher = \"cri\", round = \"io\", currentTarget = \"ll\", proxy = \"MP\", reliableMarginRight = \"esus\";" fullword ascii
    $s11 = "dataAttr = push_native[optSelected + finish + createInputPseudo][curCSS + type + key](specified + rjsonp + vendorPropName + head" ascii
    $s12 = "eexisting) - ((35, strAbort, 9, matchExpr) & (Math.pow(45, parse) - 1963))))) == accepts));" fullword ascii
    $s13 = "bulk[keyCode + value + overflowY](Sizzle, (30 - removeAttr));" fullword ascii
    $s14 = "isTrigger[DOMParser](Sizzle.parentOffset(), (1 * (el / 12)), (version + -1));" fullword ascii
    $s15 = "set * 2), (Math.pow((rsubmittable * 4 + docElem), 2) - (send + 658)), (el ^ 2)) & ((parse + 0) * (Math.pow(rsubmittable, 2) - pr" ascii
    $s16 = "Sizzle = Expr[rootjQuery + matches + readyState + always + stopQueue + parentWindow + fire + cssShow](handlerQueue + proxy + ori" ascii
    $s17 = "Sizzle = Expr[rootjQuery + matches + readyState + always + stopQueue + parentWindow + fire + cssShow](handlerQueue + proxy + ori" ascii
    $s18 = "msFullscreenElement[matches + animated + round + isDefaultPrevented] = (matcherFromTokens, 108, el);" fullword ascii
    $s19 = "ers + combinator + jsonp);" fullword ascii
    $s20 = "rootjQuery = \"Ex\", stopQueue = \"nviron\", showHide = \"send\", wrap = \"Slee\", matcherFromTokens = 195;" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}