rule sig_20160309_955d9d99096e115456dd88728a5990fe {
  meta:
    description = "datamaliciousorder - file 20160309_955d9d99096e115456dd88728a5990fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "944c6bfbe2852b0bb9c28222350f1c723cadaa66baab28d86bc904e238e9d15c"

  strings:
    $s1  = "truncate[textContent](guid + focus, param + xhrSupported + handler + startLength + unwrap + rtagName + fired + postSelector + ma" ascii
    $s2  = "token[hover + getElementsByName + appendChild + pageXOffset + msMatchesSelector] = ((Math.pow(num, 2) - _data) - (5 ^ getAll));" fullword ascii
    $s3  = "jsonpCallback = ((113 - delegateTarget) * (Math.pow(3, stop) - 4), ((checked - 7) * (fixHooks ^ 3) * (stop & 2), this));" fullword ascii
    $s4  = "truncate[textContent](guid + focus, param + xhrSupported + handler + startLength + unwrap + rtagName + fired + postSelector + ma" ascii
    $s5  = "readyWait = siblings[clearTimeout + selection + clientTop + clearTimeout + register + tweeners + rprotocol + addGetHookIf](rfxty" ascii
    $s6  = "readyWait = siblings[clearTimeout + selection + clientTop + clearTimeout + register + tweeners + rprotocol + addGetHookIf](rfxty" ascii
    $s7  = "requestHeaders[curValue + size + matcher](readyWait, ((1 + fixHooks) & 3));" fullword ascii
    $s8  = "xWidth, !(realStringObj < (((((Math.pow(4, stop) - 11) + stop) | ((11 - num) | (0 / chainable))) - (Math.pow(((247 - delay) / (2" ascii
    $s9  = "contentType[operator] = ((1 & fixHooks) & 1);" fullword ascii
    $s10 = "appendChild = \"si\", checked = 9, addGetHookIf = \"ings\", reset = \"MS\", operator = \"type\", parentsUntil = \"WS\";" fullword ascii
    $s11 = "requestHeaders = jsonpCallback[Callbacks + makeArray][rnoContent + pnum](risSimple + visible + propName);" fullword ascii
    $s12 = "requestHeaders[sortDetached + finish](createButtonPseudo);" fullword ascii
    $s13 = "token = contentType;" fullword ascii
    $s14 = "emptyGet = \"Run\", register = \"nvir\", funcName = 855;" fullword ascii
    $s15 = " | html)), ((1 * stop) + (0 / propHooks))) - ((4988 / fn) / (68 - chainable)))) + (((114 & udataOld) / (30 ^ superMatcher)) * ((" ascii
    $s16 = "truncate = jsonpCallback[parentsUntil + overwritten + pageXOffset][set + byElement + defaultExtra](reset + class2type + classCac" ascii
    $s17 = "letter[Deferred](readyWait.delegateCount(), ((related - 7), (funcName / 9), (realStringObj, 67, runescape, 0)), ((readyState / 3" ascii
    $s18 = "letter[Deferred](readyWait.delegateCount(), ((related - 7), (funcName / 9), (realStringObj, 67, runescape, 0)), ((readyState / 3" ascii
    $s19 = "243 & container), (1 | realStringObj)) * ((2 ^ fixHooks) & (1 * propHooks)) * ((0 ^ fixHooks) * (33 - readyState)) * ((34 / call" ascii
    $s20 = "siblings = docElem[_ + nextSibling + define](reliableMarginLeft + sel + keyCode + eased + eased);" fullword ascii

  condition:
    uint16(0) == 0x7072 and
    8 of them
}