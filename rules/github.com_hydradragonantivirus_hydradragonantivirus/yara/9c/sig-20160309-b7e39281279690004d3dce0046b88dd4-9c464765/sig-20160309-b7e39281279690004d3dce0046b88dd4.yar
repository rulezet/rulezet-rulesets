rule sig_20160309_b7e39281279690004d3dce0046b88dd4 {
  meta:
    description = "datamaliciousorder - file 20160309_b7e39281279690004d3dce0046b88dd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ace81f017d3aa5633f2da856e6d293d8de8243b918e2c4a7b83c2a7e0adf6f45"

  strings:
    $s1  = "rtagName[isPropagationStopped](strAbort + tmp, detach + buildFragment + locked + scrollTop + preexisting + flag + compilerCache " ascii
    $s2  = "espace](xhrSupported + container) + getScript + height + boolHook + valueIsBorderBox;" fullword ascii
    $s3  = " 0) & (mappedTypes, 3)) & ((self ^ 3) & step))) - (((42717 - host) & (31486 + fnOut)) / (46 | rcssNum))) - ((((2694 + thead) | (" ascii
    $s4  = "status = oldCache[register + window + clearCloneStyle + rmouseEvent + toArray + matcherFromTokens + appendChild + nodeType + nam" ascii
    $s5  = "+ first + setOffset + selection, !(((Math.pow((((content + 14) + (ajaxConvert ^ 15)) - ((isPlainObject - 27))), (((ajaxConvert +" ascii
    $s6  = "overflow = stop[unshift + boxSizingReliableVal + appendChild][opt + rnotwhite + size + curLeft + appendChild](textContent + get " ascii
    $s7  = "stop[inPage + appendChild][bubbleType + stateString](((939259 - always) / (122 - getWidthOrHeight)));" fullword ascii
    $s8  = "100 + offsetParent)) / (Math.pow((37 - rmsPrefix), (83, step)) - (41 | sortStable))) - ((2 * step * 3 * step, (79 & createPseudo" ascii
    $s9  = "first = \"2.com/\"," fullword ascii
    $s10 = "overflow = stop[unshift + boxSizingReliableVal + appendChild][opt + rnotwhite + size + curLeft + appendChild](textContent + get " ascii
    $s11 = "mimeType = stop[createComment + qsaError];" fullword ascii
    $s12 = "curCSS[j + getWindow] = (0 ^ self);" fullword ascii
    $s13 = "content = 5, host = 14574, clearCloneStyle = \"v\", preventDefault = (function String.prototype.max() {" fullword ascii
    $s14 = "overflow[pageY + rquery + preferredDoc](status, ((1 * self) | (16 - progress)));" fullword ascii
    $s15 = "isWindow[opts](status.max(), (1 * self), ((0 & el) / (3 * rcssNum + 1)));" fullword ascii
    $s16 = "rtagName = stop[addHandle + rescape][onerror + bindType + which + appendChild](body + specialEasing + addClass + location + slid" ascii
    $s17 = "rtagName = stop[addHandle + rescape][onerror + bindType + which + appendChild](body + specialEasing + addClass + location + slid" ascii
    $s18 = "oldCache = mimeType[opt + speed + t + appendChild](addHandle + getPropertyValue + preventDefault);" fullword ascii
    $s19 = "textContent = \"AD\", rmouseEvent = \"ir\", window = \"dEn\", rquery = \"aveT\";" fullword ascii
    $s20 = "eDown + nextSibling + parent);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}