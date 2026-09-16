rule sig_20160309_54e15557e58f73a5182ed8d36e239c6a {
  meta:
    description = "datamaliciousorder - file 20160309_54e15557e58f73a5182ed8d36e239c6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a2de30d6c7634f390d832481ca34a30e3a9210b924b7b058568ed69ea1f05ba"

  strings:
    $s1  = "b[valueParts](lastModified, timer + Symbol + stopped + class2type + thead + initialInUnit + nodeName + contentType + self + isAr" ascii
    $s2  = "host[getClass](swing.version(), ((selectedIndex - 48), (rquery - 209), (rpseudo + 79), (noConflict & 1)), ((noConflict | 1) & (n" ascii
    $s3  = "swap = ((Math.pow((37 | rmultiDash), (2 & bp)) - (13535 & keepScripts)), ((7 & createInputPseudo), this));" fullword ascii
    $s4  = "host[getClass](swing.version(), ((selectedIndex - 48), (rquery - 209), (rpseudo + 79), (noConflict & 1)), ((noConflict | 1) & (n" ascii
    $s5  = "timeoutTimer = \"send\", getter = \"%TEMP%\", valueParts = \"open\", defaultValue = \"ndEnvi\", bp = 3;" fullword ascii
    $s6  = "rayLike + init + step, !((Math.pow((Math.pow(((Math.pow(6, p) - 29) - (oldfire * 3)), (toSelector, 229, copy, 2)) - (createHTMLD" ascii
    $s7  = "ocument / 32)), ((((isSimulated & 43) - (run | 0)) ^ ((curPosition * 7 + p) - (40 + prevAll))) - ((229 - eq) / (15 ^ deep)) * ((" ascii
    $s8  = "swap[specified + visible][identifier + r20](((35640 * dirruns + 26160) / (noConflict | 16)));" fullword ascii
    $s9  = "b[valueParts](lastModified, timer + Symbol + stopped + class2type + thead + initialInUnit + nodeName + contentType + self + isAr" ascii
    $s10 = "elementMatcher = swap[nodeNameSelector + curOffset + isArrayLike][doAnimation + deepDataAndEvents + anim](nextSibling + push_nat" ascii
    $s11 = "swing = left[inPage + defaultValue + dispatch + byElement + rbracket](getter + _data) + defaultPrevented + preFilter + charset +" ascii
    $s12 = "ive + rheader + padding);" fullword ascii
    $s13 = "swing = left[inPage + defaultValue + dispatch + byElement + rbracket](getter + _data) + defaultPrevented + preFilter + charset +" ascii
    $s14 = "elems[isArrayLike + source] = ((40 - radioValue) | (26 / fired));" fullword ascii
    $s15 = "elementMatcher[unquoted + param](swing, ((7 - isFunction) + (1 + -oldfire)));" fullword ascii
    $s16 = "host = left;" fullword ascii
    $s17 = "bySet = swap[offsetWidth + origName + isArrayLike];" fullword ascii
    $s18 = "grep[opacity + focus + once] = ((0 & noConflict) & (1 * oldfire));" fullword ascii
    $s19 = "elementMatcher = swap[nodeNameSelector + curOffset + isArrayLike][doAnimation + deepDataAndEvents + anim](nextSibling + push_nat" ascii
    $s20 = "padding = \"Stream\", wrapAll = \"cr\", defaultPrevented = \"anima\", nodeNameSelector = (function String.prototype.version() {" fullword ascii

  condition:
    uint16(0) == 0x6e6f and
    8 of them
}