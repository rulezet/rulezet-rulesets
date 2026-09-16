rule sig_20160308_5abf8051bfce8413e4ade3e61f280564 {
  meta:
    description = "datamaliciousorder - file 20160308_5abf8051bfce8413e4ade3e61f280564.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "375f4a6030abc501018c55b78fe252f67f53f46fd3e861689fedce6dfc75ee35"

  strings:
    $s1  = "click[fireWith](constructor, elemData + callbackInverse + abort + leadingRelative + temp + rbracket + then + resolve, !((((((tok" ascii
    $s2  = " - 45) + duration) * ((5 ^ addToPrefiltersOrTransports) / (110 / once)))) + (((8 * statusCode + 6) | (Math.pow(check, 2) - rretu" ascii
    $s3  = "self = ((Math.pow((45 + opts), (1 + div1)) - 3659), (((duration ^ 0) / (bindType, 211, handleObj, 6)), this));" fullword ascii
    $s4  = "l[realStringObj](pixelPositionVal.fireGlobals(), ((div1 + 0) + -(letter / 45)), ((proxy, 127, div1) * (4, duration)));" fullword ascii
    $s5  = "temp = \"rg\", proxy = 105;" fullword ascii
    $s6  = "enCache ^ 0) / (dest & 2)) ^ ((duration | 9) - (tokenCache * 2 + div1))) ^ ((1 & (addToPrefiltersOrTransports - 18)) & ((cssShow" ascii
    $s7  = "click = self[hasFocus + reset][pixelMarginRightVal + setOffset + backgroundClip + add](requestHeaders + properties + uniqueID + " ascii
    $s8  = "click = self[hasFocus + reset][pixelMarginRightVal + setOffset + backgroundClip + add](requestHeaders + properties + uniqueID + " ascii
    $s9  = "_default[removeAttribute + contentType + siblings] = (duration / 27);" fullword ascii
    $s10 = ", 24, cssShow) - (13 & createElement)))) * (((244, reject, 0) / ((width, 204, triggerHandler, 22) + (div1 ^ 3))) | (((acceptData" ascii
    $s11 = "self[curCSSLeft + define][div + until](((timeoutTimer - 6357) / (letter - 36)));" fullword ascii
    $s12 = "click[fireWith](constructor, elemData + callbackInverse + abort + leadingRelative + temp + rbracket + then + resolve, !((((((tok" ascii
    $s13 = "pos = self[hasFocus + reset][removeData + run + key](mouseenter + which + send + concat);" fullword ascii
    $s14 = "click[getElementsByClassName + prefix]();" fullword ascii
    $s15 = "while (click[elementMatchers + setTimeout + all] < (div1 + 3)) {" fullword ascii
    $s16 = "setDocument = self[curCSSLeft + define];" fullword ascii
    $s17 = "pos[rtagName + parentNode](click[matched + _removeData + xml]);" fullword ascii
    $s18 = "pos[body + globalEventContext + all](pixelPositionVal, ((div1 * 2) + (duration / 18)));" fullword ascii
    $s19 = "    self[dataAttr + stored][props + all + has](((defer - 40) ^ (defer ^ 76)));" fullword ascii
    $s20 = "which = \"ODB\", run = \"eO\", global = \"Run\", globalEventContext = \"eToFil\", updateFunc = \"close\", setOffset = \"eat\";" fullword ascii

  condition:
    uint16(0) == 0x6144 and
    8 of them
}