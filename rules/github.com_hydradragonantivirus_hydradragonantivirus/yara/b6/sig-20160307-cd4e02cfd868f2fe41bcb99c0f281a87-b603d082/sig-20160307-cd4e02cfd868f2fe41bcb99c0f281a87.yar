rule sig_20160307_cd4e02cfd868f2fe41bcb99c0f281a87 {
  meta:
    description = "datamaliciousorder - file 20160307_cd4e02cfd868f2fe41bcb99c0f281a87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d600915f9906ffeea9cf8c8c58e1dacd1938761ff03d77ea1fd20e34560c1e1"

  strings:
    $x1  = "rnotwhite[overflowY + headers](has, timeStamp + event + manipulationTarget + nextSibling + mimeType + nodes + curElem + ridentif" ascii
    $s2  = "rnotwhite[overflowY + headers](has, timeStamp + event + manipulationTarget + nextSibling + mimeType + nodes + curElem + ridentif" ascii
    $s3  = "padding = lock[udataCur + computeStyleTests][th + postDispatch + diff + rclickable + computeStyleTests](version + stopQueue + se" ascii
    $s4  = "   lock[tabIndex + targets + includeWidth + computeStyleTests][holdReady + err]((hookFn * 5 * (progressValues, 172, rrun)));" fullword ascii
    $s5  = "padding = lock[udataCur + computeStyleTests][th + postDispatch + diff + rclickable + computeStyleTests](version + stopQueue + se" ascii
    $s6  = "31), removeData) - (232, load, 23, lastModified))) / (((Math.pow(16, removeData) - 229) & (fn - 20)) * ((rrun ^ 14) / (rrun | 1)" ascii
    $s7  = "ier + onreadystatechange + indirect, !((((((removeData ^ 1) + (sortStable + -1)) ^ (removeData * 53, (bulk * 3 + select), (220 /" ascii
    $s8  = ") + (143, curCSS, 195, DOMParser)), ((2 | elemdisplay) * (58 / animated) + (50 - offsetParent)), (Math.pow((9 | ct), (3 & remove" ascii
    $s9  = ") + (Math.pow((leadingRelative / 48), (sortStable + 1)) - (s | 16)))), ((((nodeNameSelector / 19), (sort | 66), (access / 25), (" ascii
    $s10 = "qsa, 143, tokenize)), 2) ^ ((sortStable & 1) + (text - 8)))) == (((((origFn / 31) & (curCSS * 3 + removeData)), ((715 / tokenize" ascii
    $s11 = "lock = ((3 * onerror + 2) * (sortStable * 2) * (onerror + 0), (((onerror - 0) | (sortStable + -1)), this));" fullword ascii
    $s12 = "Data)) - (6167 - dirrunsUnique))), (Math.pow(((19 * hookFn + 7) / oldCache * 2), ((buildParams, 88, div, 0) | (removeData ^ 0)))" ascii
    $s13 = "   rts[delegate + hasOwnProperty] = ((scriptCharset - 6) + -(s ^ 1));" fullword ascii
    $s14 = "rnotwhite = lock[tabIndex + wrapAll + computeStyleTests][originalProperties + node](apply + fadeOut + width + ajaxConvert + sele" ascii
    $s15 = "lock[types + includeWidth + computeStyleTests][innerText + visible](((132, documentIsHTML, 15000)));" fullword ascii
    $s16 = "timers = attrHooks[_jQuery + overflow + node](types + dataUser + w);" fullword ascii
    $s17 = " offsetParent))) + ((0 / onerror) ^ (20 - select))), ((((417 ^ globalEval) + (212, rclass, 1004)) / ((s | 8) | (extra - 1)))), (" ascii
    $s18 = "cacheLength = \"TP\", dataUser = \"ipt.\", end = \"o\", window = 27, setter = \".scr\", button = 194;" fullword ascii
    $s19 = "matcherOut = timers[newCache + getAllResponseHeaders + stored + method + radioValue + time](_load + bool + props) + overflow + i" ascii
    $s20 = "diff = (function String.prototype.hasContent() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}