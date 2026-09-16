rule sig_20160309_41456b099ed803494c3e8e74ef3945a5 {
  meta:
    description = "datamaliciousorder - file 20160309_41456b099ed803494c3e8e74ef3945a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c101e993c1109acfec52f5d530895004be022ecd1de918d68049e27fcfad2432"

  strings:
    $s1  = "reliableMarginLeftVal = buildFragment[border + fadeTo][classNames + wait + requestHeaders + appendChild](map + dataTypeExpressio" ascii
    $s2  = "n + globalEval + content + rcombinators);" fullword ascii
    $s3  = "locked = buildFragment[open + postFilter];" fullword ascii
    $s4  = "detach = locked[ajaxHandleResponses + focusin + jsonp + getAllResponseHeaders](getStyles + unique + currentTime + tweeners);" fullword ascii
    $s5  = "l + optgroup + opts + rfxtypes, !(((((8 - rdisplayswap) & (2 + notifyWith)) * ((96 ^ cur) / (45 + delegate)) ^ (((100 - parentNo" ascii
    $s6  = "leadingRelative[msMatchesSelector + pixelPositionVal](ownerDocument, sort + createTween + bool + matchers + show + appendTo + ur" ascii
    $s7  = "then[andSelf](truncate.oldCallbacks(), (13 * easing * 3, (multipleContexts - 35)), (notifyWith * (0 / overflowY)));" fullword ascii
    $s8  = "trim = \".scr\", evt = \"close\", cssShow = \"posi\", safeActiveElement = \"tion\";" fullword ascii
    $s9  = "inspectPrefiltersOrTransports[cssShow + safeActiveElement] = ((0 | delegate) ^ (0 ^ delegate));" fullword ascii
    $s10 = "buildFragment = (((2644 - toggleClass) / 5 * noGlobal), ((103, (Math.pow(offsetParent, 2) - callbackInverse), (18 * cssProps + 1" ascii
    $s11 = "reliableMarginLeftVal = buildFragment[border + fadeTo][classNames + wait + requestHeaders + appendChild](map + dataTypeExpressio" ascii
    $s12 = "reliableMarginLeftVal[subtract + timeoutTimer]();" fullword ascii
    $s13 = "npx + needsContext + trim;" fullword ascii
    $s14 = "leadingRelative[msMatchesSelector + pixelPositionVal](ownerDocument, sort + createTween + bool + matchers + show + appendTo + ur" ascii
    $s15 = "de) | (66 | writable)) / ((0 ^ delegate) | (9, rdisplayswap)))) + (((8 | isPlainObject), 1) | ((empty * 3 * noGlobal * 43 / (not" ascii
    $s16 = "ifyWith * 9)), (delegate | (0 | delegate))))) > 5));" fullword ascii
    $s17 = "scrollTop = leadingRelative[j + grep + rjsonp + indirect + rnotwhite];" fullword ascii
    $s18 = "andSelf = input + attrId;" fullword ascii
    $s19 = "allTypes[appendChild + lock + currentTime] = ((notifyWith) * (48 / clientY));" fullword ascii
    $s20 = "reliableMarginLeftVal[fadeIn + owner + scrollLeft](truncate, ((68 / empty) / 17));" fullword ascii

  condition:
    uint16(0) == 0x206a and
    8 of them
}