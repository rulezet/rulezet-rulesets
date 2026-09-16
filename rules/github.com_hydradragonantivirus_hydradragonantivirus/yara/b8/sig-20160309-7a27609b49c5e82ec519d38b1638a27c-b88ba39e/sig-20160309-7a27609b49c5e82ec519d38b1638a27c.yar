rule sig_20160309_7a27609b49c5e82ec519d38b1638a27c {
  meta:
    description = "datamaliciousorder - file 20160309_7a27609b49c5e82ec519d38b1638a27c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8558bf7d539e9a6545d7eeb9d19008cfd3903d3f064a7ae8bd3988c5a1ac137b"

  strings:
    $s1  = "delegateTarget = matcherIn[createTextNode + elementMatcher][rchecked + collection + string + inPage + matchers](hasContent + rev" ascii
    $s2  = "params[delay + className](matchExpr + headers, winnow + matchesSelector + defaultPrevented + i + rbrace + msg + push_native + so" ascii
    $s3  = "delegateTarget = matcherIn[createTextNode + elementMatcher][rchecked + collection + string + inPage + matchers](hasContent + rev" ascii
    $s4  = "delegateTarget[activeElement + isLocal](hidden, (opacity ^ (21 - lname)));" fullword ascii
    $s5  = "Index)) + ((83 - tabIndex) - (1590 / onreadystatechange)))) - (Math.pow((((594 + fadeIn) - (229, nodeType, 307)) / (conv2 & (14 " ascii
    $s6  = "delegateTarget[noop + ontype](tokens);" fullword ascii
    $s7  = "erse + eventHandle + returned + progressValues + getScript);" fullword ascii
    $s8  = "matcherIn[version + i][_jQuery + pointerleave](((Math.pow(9306, siblingCheck) - 86586629) & (deepDataAndEvents & 16379)));" fullword ascii
    $s9  = "attaches[elems](hidden.postDispatch(), (opacity * (44, ajaxPrefilter, 173, wrapInner)), ((16 - markFunction) - (559 / getJSON)))" ascii
    $s10 = "attaches[elems](hidden.postDispatch(), (opacity * (44, ajaxPrefilter, 173, wrapInner)), ((16 - markFunction) - (559 / getJSON)))" ascii
    $s11 = "rtDetached + window + rlocalProtocol + selectedIndex + protocol + postMap + extra + slideUp + i, !((((((keepData - 11) / (getCla" ascii
    $s12 = "button[i + ajaxSettings] = ((252 / uid) - (21 + bind));" fullword ascii
    $s13 = "params = matcherIn[version + i][stopImmediatePropagation + ajaxSetup + originalOptions + marginRight + i](andSelf + invert + key" ascii
    $s14 = "params = matcherIn[version + i][stopImmediatePropagation + ajaxSetup + originalOptions + marginRight + i](andSelf + invert + key" ascii
    $s15 = "button = delegateTarget;" fullword ascii
    $s16 = "relatedTarget = button;" fullword ascii
    $s17 = "+ opacity))), ((0 | wrapInner) ^ 2)) - (((_load * 33 + opacity) - (4 | getBoundingClientRect)) | ((194 ^ class2type) + (296 + no" ascii
    $s18 = "postFinder = \"Cre\", createTextNode = \"WScr\", inspectPrefiltersOrTransports = \"ope\", getBoundingClientRect = 67, protocol =" ascii
    $s19 = "tokens = params[animation + focusin + margin];" fullword ascii
    $s20 = "matcherIn = (((44 * siblingCheck + 13) | (tmp - 64)), (((fixHooks / 48) - (escapedWhitespace & 11)), this));" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}