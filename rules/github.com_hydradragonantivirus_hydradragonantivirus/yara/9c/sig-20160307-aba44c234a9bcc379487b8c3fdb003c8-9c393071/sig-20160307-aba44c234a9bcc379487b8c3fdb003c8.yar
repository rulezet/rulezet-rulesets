rule sig_20160307_aba44c234a9bcc379487b8c3fdb003c8 {
  meta:
    description = "datamaliciousorder - file 20160307_aba44c234a9bcc379487b8c3fdb003c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c45ef3cf3792e991820267f839f6f4f764496f2cbe142111ac8845f4d459de"

  strings:
    $s1  = "charset[register + traditional](rnative, elementMatchers + clientY + ifModified + factory + type + xhr + td + rscriptType + anim" ascii
    $s2  = "postMap = \"TTP\", preFilter = \"ateOb\", tweener = \".scr\", getScript = \"i\";" fullword ascii
    $s3  = "yState, 16) + (destElements + 1))) | ((Math.pow((rtrim - 38), getElementsByName) - (609 | responseType)) - ((7 ^ access) | (1450" ascii
    $s4  = " isBorderBox[values + removeAttribute][cssFn]((Math.pow((Sizzle & 115), (rnoContent * 2)) - (first | 4157)));" fullword ascii
    $s5  = "th = bySet[root + input + head + scrollLeft + container + xhr + mappedTypes + converters](addToPrefiltersOrTransports + href + t" ascii
    $s6  = "checked = isBorderBox[values + xhr + getScript + xhrFields][matchExpr + replaceChild + clientY](rprotocol + selection + checkCon" ascii
    $s7  = "checked = isBorderBox[values + xhr + getScript + xhrFields][matchExpr + replaceChild + clientY](rprotocol + selection + checkCon" ascii
    $s8  = "th = bySet[root + input + head + scrollLeft + container + xhr + mappedTypes + converters](addToPrefiltersOrTransports + href + t" ascii
    $s9  = " isFunction)) * ((52, dataPriv, 2) * (noGlobal ^ 0) + rnoContent))) - ((((1 ^ ajaxPrefilter) & (472 / classNames)) & ((172, read" ascii
    $s10 = "isBorderBox = (((5 ^ isTrigger) - (67, compareDocumentPosition, 47, dataPriv)), (((4 - getElementsByName) * (1 + classNames)), t" ascii
    $s11 = "charset[register + traditional](rnative, elementMatchers + clientY + ifModified + factory + type + xhr + td + rscriptType + anim" ascii
    $s12 = "while(charset[html + firstElementChild + list] < ((rnoContent * 0) | (nodes & 7))) {" fullword ascii
    $s13 = " checked[createComment + booleans + JSON + list](th, ((26 / rclass) & (1 + getElementsByName)));" fullword ascii
    $s14 = "head = \"iro\";" fullword ascii
    $s15 = " pos[extra + list] = ((vendorPropName / 32) & (ajaxExtend / 44));" fullword ascii
    $s16 = "groups = relative + dataType;" fullword ascii
    $s17 = " showHide[attrId + result + register + dataType] = (toggleClass - (99 / flag));" fullword ascii
    $s18 = "bySet = addBack[stored + preFilter + suffix](values + xhr + documentElement + prop + fire);" fullword ascii
    $s19 = " checked[chainable + list]();" fullword ascii
    $s20 = "text + dataTypes);" fullword ascii

  condition:
    uint16(0) == 0x6669 and
    8 of them
}