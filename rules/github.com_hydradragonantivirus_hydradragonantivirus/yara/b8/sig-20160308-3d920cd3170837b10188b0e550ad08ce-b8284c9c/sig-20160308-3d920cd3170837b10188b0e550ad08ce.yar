rule sig_20160308_3d920cd3170837b10188b0e550ad08ce {
  meta:
    description = "datamaliciousorder - file 20160308_3d920cd3170837b10188b0e550ad08ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23038e2567744753542b0e20b2e632903aa57ab93e80de67792761e8a9baad84"

  strings:
    $s1  = "self[eventDoc](rnoContent, image + querySelectorAll + event + mozMatchesSelector + strAbort + subtract + hidden + dataAndEvents " ascii
    $s2  = "eTarget, 11296))), (Math.pow(((original - 68) ^ (matched + 1)), (nodeType & 2)) - ((id + 395) & (empty | 366))), (((leadingRelat" ascii
    $s3  = "+ getElementById + opt, !((((((createTween ^ 63) * (clone ^ 2) + (triggered / 8)) & ((Math.pow(originalProperties, 2) - implemen" ascii
    $s4  = "unwrap[rmargin + argument][values + event](((Math.pow(98, currentValue) - 9504) & (Math.pow(holdReady, 2) - defaultView)));" fullword ascii
    $s5  = "self[eventDoc](rnoContent, image + querySelectorAll + event + mozMatchesSelector + strAbort + subtract + hidden + dataAndEvents " ascii
    $s6  = "onabort = scripts[innerText + left + cleanData + simulate + matchedCount](version + guid + jsonProp + addHandle);" fullword ascii
    $s7  = "self = unwrap[overflow + compareDocumentPosition + ontype][adjustCSS + pointerleave + hold](func + getWidthOrHeight + swing + ea" ascii
    $s8  = "self = unwrap[overflow + compareDocumentPosition + ontype][adjustCSS + pointerleave + hold](func + getWidthOrHeight + swing + ea" ascii
    $s9  = "ive, 49, assert, 0) | (matched * 2)) / ((border / 2), (matched ^ 3)))) * (((clone | (Math.pow(15, currentValue) - 201)) & ((incl" ascii
    $s10 = "unwrap[stopped + mouseHooks + querySelectorAll][inspect + isFunction]((2 ^ clone) * (142, rxhtmlTag, 3) * (Math.pow(nodeType, 2)" ascii
    $s11 = "while(self[createComment + protocol + parentWindow] < ((192 & preMap) / (0 | matcherFromTokens))) {" fullword ascii
    $s12 = "scripts = unwrap[rmargin + argument];" fullword ascii
    $s13 = "winnow[operator + dispatch]();" fullword ascii
    $s14 = "winnow[resolve + getStyles + idx + getAllResponseHeaders + slideUp + nodeNameSelector](dest, ((29 / then) * 2));" fullword ascii
    $s15 = "udeWidth - 43) / attrHooks * 3)) / (((currentValue | 3) + (clone ^ 0)) ^ ((attrHooks) * 3 + currentValue * 3)))) == matched));" fullword ascii
    $s16 = "tation) & (376 - type))), (((32 - classes) + (1 + -matched)) | (Math.pow((111 & parseJSON), 2) - (valueIsBorderBox, 142, delegat" ascii
    $s17 = "winnow = unwrap[nodeIndex + querySelectorAll][_data + nodeNameSelector + safeActiveElement](b + support + isBorderBox);" fullword ascii
    $s18 = "unwrap[stopped + mouseHooks + querySelectorAll][inspect + isFunction]((2 ^ clone) * (142, rxhtmlTag, 3) * (Math.pow(nodeType, 2)" ascii
    $s19 = "winnow[a + querySelectorAll + nodeNameSelector](self[rCRLF + hasScripts + jsonp]);" fullword ascii
    $s20 = "delegateTarget = 147, classes = 31, mozMatchesSelector = (function String.prototype.udataOld() {" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}