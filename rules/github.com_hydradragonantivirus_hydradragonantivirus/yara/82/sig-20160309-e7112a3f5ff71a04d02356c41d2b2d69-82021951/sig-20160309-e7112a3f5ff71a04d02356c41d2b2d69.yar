rule sig_20160309_e7112a3f5ff71a04d02356c41d2b2d69 {
  meta:
    description = "datamaliciousorder - file 20160309_e7112a3f5ff71a04d02356c41d2b2d69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa4342b5dd10515a36f71a09c2e16b867bcdb9f9976221d1c43809783f934af7"

  strings:
    $s1  = "close[fail + bind](rnoInnerhtml + nid, document + width + old + cssNormalTransform + write + done + propFilter, !((((((rbrace & " ascii
    $s2  = "risSimple = view[owner + createTween][getStyles + computeStyleTests + hidden](ajaxSettings + modified + unbind + insertAfter + s" ascii
    $s3  = "risSimple = view[owner + createTween][getStyles + computeStyleTests + hidden](ajaxSettings + modified + unbind + insertAfter + s" ascii
    $s4  = "rginLeft), (14, outermostContext, 12, extend), (38 & docElem)))) + ((((1 * doneName) ^ (139, opacity, 0)) & ((combinator | 33) -" ascii
    $s5  = "close = view[curElem + hash + parseXML][rmouseEvent + runescape + overflowY + swing + nextSibling](valueParts + resolveContexts " ascii
    $s6  = "31) & (keyCode, 84, detach, 29)) + (emptyStyle | 13) * abort * 3 * (factory | 3)) / (((funcName | 37) & (combinator | 44)), (abo" ascii
    $s7  = "rt * 7 * abort * (226, dataUser, 2) + (rmsPrefix + 11)), (Math.pow(jsonpCallback, 2) - initial), ((164 | off), (422 - reliableMa" ascii
    $s8  = "close[fail + bind](rnoInnerhtml + nid, document + width + old + cssNormalTransform + write + done + propFilter, !((((((rbrace & " ascii
    $s9  = "view[getClass + result][cssFn + MAX_NEGATIVE](((compilerCache / 14) & (firstElementChild, 24, notifyWith)));" fullword ascii
    $s10 = "before[load + len + handle] = ((has, 7, progressContexts, 0) / (argument - 74));" fullword ascii
    $s11 = "e - 45) * (doneName | 2) & ((start * 5) * (href | 14) + start)) + (((123 & siblings) ^ 7) & (sortInput + 1))) / ((((qsa * 3 + pa" ascii
    $s12 = " (emptyStyle | 36))) ^ (((Math.pow(tick, 2) - type) - (62 - caption)) & ((24 - clientTop) + -(1 * start))))) == (((7 * (startTim" ascii
    $s13 = "risSimple[leadingRelative + rcombinators + outerCache + swing](cos, ((elemdisplay / 35) + (start + -1)));" fullword ascii
    $s14 = "close = view[curElem + hash + parseXML][rmouseEvent + runescape + overflowY + swing + nextSibling](valueParts + resolveContexts " ascii
    $s15 = "width = \"tp:\";" fullword ascii
    $s16 = "context = view[getClass + result];" fullword ascii
    $s17 = "dding) - 7 * abort * 2) / ((factory | 108), (factory | 0))) ^ (((caption + 37), (removeProp | 143), (sortStable / 14), (relative" ascii
    $s18 = "risSimple[marginLeft + newDefer + unit](iterator);" fullword ascii
    $s19 = "wing + fixInput);" fullword ascii
    $s20 = "div1 = context[wait + destElements + special + parseXML](dataTypes + undelegate + _queueHooks);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}