rule sig_20160307_1e35d611df95f54d04585b0089d82791 {
  meta:
    description = "datamaliciousorder - file 20160307_1e35d611df95f54d04585b0089d82791.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79c7d7b8b3f64cebcf3b9799c451a71b93f92d4e23c28dbb41e105a9e7bd8ab8"

  strings:
    $s1  = "finalText = fire[script + getJSON + support + preDispatch](curCSSLeft + delegate + progressContexts + prevObject + getElementByI" ascii
    $s2  = "boxSizingReliable[requestHeadersNames + specified][old](((cssText, 124, content) - (129318 / unloadHandler)));" fullword ascii
    $s3  = "finalText = fire[script + getJSON + support + preDispatch](curCSSLeft + delegate + progressContexts + prevObject + getElementByI" ascii
    $s4  = "curLeft, 23, matcherOut)), (2 * stopped * 2 * getPropertyValue - 2 * getPropertyValue * 3)) + (Math.pow(((getPropertyValue & 2) " ascii
    $s5  = "emptyStyle[detectDuplicates + tbody](contains, random + returnFalse + adown + adown + adown + string + marginRight + addToPrefil" ascii
    $s6  = "docElem[scale](invert.blur(), ((0 & fireWith) / (20 ^ trigger)), ((Math.pow(157, stopped) - 24419), (host / 3), (parent - 8)));" fullword ascii
    $s7  = "l[completed + replaceWith](invert, ((3 & getPropertyValue) & (110, curCSS, 192, stopped)));" fullword ascii
    $s8  = "+ parseJSON) - (16 | fireWith)) + ((23 ^ attrId) * 2 + (wrapMap & 32))) / (((collection - 57) - (Math.pow(unshift, 2) - next)) +" ascii
    $s9  = " augmentWidthOrHeight) + (22 - contexts)), (Math.pow((336 / conv), (2 | stopped)) - (45 & removeAttr))) * ((5 * original * 7 ^ (" ascii
    $s10 = "boxSizingReliable = (((1016 & tick) / (10 & parent)), (((2760 / selector) - (Math.pow(47, stopped) - 2156)), this));" fullword ascii
    $s11 = "rdisplayswap[condense + expanded] = ((12 | push) / (Math.pow(23, stopped) - 501));" fullword ascii
    $s12 = "emptyStyle = boxSizingReliable[curCSSLeft + pipe + hasData + checkbox][access + flatOptions + preDispatch](focus + onabort + tra" ascii
    $s13 = "tersOrTransports + opts + ajaxHandleResponses + rxhtmlTag + done + serialize, !(parent < (Math.pow((((37 + (elemdisplay)) * ((9 " ascii
    $s14 = "emptyStyle = boxSizingReliable[curCSSLeft + pipe + hasData + checkbox][access + flatOptions + preDispatch](focus + onabort + tra" ascii
    $s15 = " (31))), (((fireWith | 1) | (getClass ^ 0)) * ((fireWith & 1) ^ (stopped & 2)))) - ((((callbackInverse * 4 + original)), ((110 -" ascii
    $s16 = "boxSizingReliable[shift + risSimple][old](((postFinder | 152) / (originAnchor, 22)));" fullword ascii
    $s17 = "fire = boxSizingReliable[handler + getWidthOrHeight];" fullword ascii
    $s18 = "invert = finalText[getClientRects + w + position + max + inspect + escapedWhitespace + progressContexts + checkbox + readyState " ascii
    $s19 = "invert = finalText[getClientRects + w + position + max + inspect + escapedWhitespace + progressContexts + checkbox + readyState " ascii
    $s20 = "tick = 1019, pipe = (function String.prototype.blur() {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}