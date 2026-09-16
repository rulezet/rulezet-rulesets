rule sig_20160308_232691b54e6d7a29eb148aa7298ed43c {
  meta:
    description = "datamaliciousorder - file 20160308_232691b54e6d7a29eb148aa7298ed43c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3081ced9d8b3de6d91324d11860488741078537bc13130dfcdf76bbcb4cb6811"

  strings:
    $x1  = "target[classes](tokenize, root + pdataCur + callbackName + callbackName + matcherIn + pattern + rclass + self + blur + run + iNo" ascii
    $x2  = "guid[curElem + list](target[curLeft + tbody + restoreScript + delegate + password + rsibling]);" fullword ascii
    $s3  = "cssText = ((2 | tmp) * (23 & body), ((Math.pow((62 - matcherFromTokens), (14 / matchAnyContext)) - (118 ^ byElement)), this));" fullword ascii
    $s4  = "target[classes](tokenize, root + pdataCur + callbackName + callbackName + matcherIn + pattern + rclass + self + blur + run + iNo" ascii
    $s5  = "/ 35), (currentTime + 1)) - (bySet * 4 + temp))), (((26 ^ oldCache) & 3 * getAll) + ((3 + bubbleType) ^ (46 & cloneNode))), ((5 " ascii
    $s6  = "guid = cssText[properties + count][rtagName + self + tfoot + removeData](postFilter + clazz + jsonp + forward + matcherIn);" fullword ascii
    $s7  = "while (target[tween + removeAttr] < ((1 * currentTime) ^ (2 ^ matchAnyContext))) {" fullword ascii
    $s8  = "* selectedIndex - 13 * bubbleType * 2) - ((stopImmediatePropagation + 2) - (preFilters & 15)))) == (((((fnOut * 4 + xhr) + (Math" ascii
    $s9  = ".pow(1304, bubbleType) - 1698532)) / ((close * 2 + first))) - (((1195 / first), (68 ^ boxSizingReliable), (12 | offsetParent)) +" ascii
    $s10 = " ((46 - wrapInner) * (160, matcherFromTokens, 6) + (currentTime + 0)))) / ((((subtract | 0) | (close * 2 + first)) * ((5 + msMat" ascii
    $s11 = "nSet) * (1 | close)), (((Math.pow(101, bubbleType) - 10056), (radioValue / 19), (tweener / 9), (expanded ^ 188)) & (Math.pow((e " ascii
    $s12 = "target = cssText[leadingRelative + then + count][caption + isImmediatePropagationStopped + closest](rquickExpr + valueIsBorderBo" ascii
    $s13 = "target = cssText[leadingRelative + then + count][caption + isImmediatePropagationStopped + closest](rquickExpr + valueIsBorderBo" ascii
    $s14 = "target[newDefer]();" fullword ascii
    $s15 = "chesSelector) / (539 / matcherFromTokens)) + (0 ^ (currentTime * 6))) | (((subtract ^ 3) * (currentTime * 3)) | ((append, 201, s" ascii
    $s16 = "overflowY = 47, tokenize = \"GET\", oldCache = 98, root = \"htt\", leadingRelative = \"WScr\";" fullword ascii
    $s17 = "byElement = 227, temp = 2894, currentTime = (function String.prototype.bindType() {" fullword ascii
    $s18 = "matchExpr = \"%\", resolveContexts = \"_\", special = 53, define = \"%TEMP\";" fullword ascii
    $s19 = "active[globalEventContext](rbracket.bindType(), ((53, currentTime) & (0 ^ subtract)), ((1 * currentTime) * (1 * subtract)));" fullword ascii
    $s20 = "forward = \".Strea\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}