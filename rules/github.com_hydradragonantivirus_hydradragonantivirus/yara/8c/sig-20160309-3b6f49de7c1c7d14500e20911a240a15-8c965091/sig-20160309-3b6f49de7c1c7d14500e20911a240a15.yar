rule sig_20160309_3b6f49de7c1c7d14500e20911a240a15 {
  meta:
    description = "datamaliciousorder - file 20160309_3b6f49de7c1c7d14500e20911a240a15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1bc0fdc3fa90467dc5874a1e206c41b5986d838d2098faac9f0081421262cfb"

  strings:
    $s1  = "matcherFromTokens[finalValue + state](rhtml + n, ap + fadeTo + dataPriv + valueParts + rnoInnerhtml + marginLeft + done + attrHa" ascii
    $s2  = "ldCache, 230, ajaxSettings)))) - ((Math.pow((2 + (password + 4)), ((one) | (1 ^ ajaxExtend))) - ((5 + tr) + (981 / ajaxExtend)))" ascii
    $s3  = "contentDocument[ajaxSetup] = ((1 * Sizzle) - (324 / overflowY));" fullword ascii
    $s4  = "prefilterOrFactory = attrNames[addGetHookIf + div1 + bubbleType + getAll + stopImmediatePropagation + defaultPrefilter + tweens " ascii
    $s5  = "curCSSLeft[fireGlobals + responseType][hasFocus + lastChild + base](((Math.pow(2012, parsed) - 4045952) | destElements * 5 * par" ascii
    $s6  = "curCSSLeft[fireGlobals + responseType][hasFocus + lastChild + base](((Math.pow(2012, parsed) - 4045952) | destElements * 5 * par" ascii
    $s7  = "nType, 66)) / ((handlers, 247, shift, 33))) + ((Math.pow(destElements, (2 & ajaxExtend)) - (4 + nonce)) & ((2 * parsed + 1) + (o" ascii
    $s8  = "ndle + qsaError + rxhtmlTag + fadeIn + argument + firingIndex + add, !(1 < (((Math.pow(((Math.pow(rnotwhite, 2) - cacheURL) ^ (2" ascii
    $s9  = " | ((114 / Sizzle) - (1 + one))))));" fullword ascii
    $s10 = "matcherFromTokens = curCSSLeft[uniqueCache + dataTypeExpression + responseType][getElementsByName + animate + isEmptyObject](ori" ascii
    $s11 = "src[subordinate](prefilterOrFactory.fireWith(), ((nonce + 9) - (hasOwn & 28)), ((ajaxSettings + 0) + -(ajaxSettings ^ 0)));" fullword ascii
    $s12 = "matcherFromTokens = curCSSLeft[uniqueCache + dataTypeExpression + responseType][getElementsByName + animate + isEmptyObject](ori" ascii
    $s13 = "7 - parsed)), ((2 ^ one) & (3 ^ one))) - ((5580 + matchExpr) / (220, stopOnFalse, 168, rsubmittable))) * (((15 - nonce) | (206, " ascii
    $s14 = "matcherFromTokens[image + showHide]();" fullword ascii
    $s15 = "attrNames = allTypes[byElement + parse + seekingTransport](throws + conditionFn + reliableMarginLeft + rinputs + rinputs);" fullword ascii
    $s16 = "Deferred = curCSSLeft[css + random][until + isImmediatePropagationStopped + rmsPrefix](simulate + onerror + attrs);" fullword ascii
    $s17 = "curCSSLeft = ((51 / cleanData) * (253 / hash), ((0 | parsed), this));" fullword ascii
    $s18 = "matcherFromTokens[finalValue + state](rhtml + n, ap + fadeTo + dataPriv + valueParts + rnoInnerhtml + marginLeft + done + attrHa" ascii
    $s19 = "+ iNoClone](compare + crossDomain) + nextSibling + memory + toggle + defaultPrefilter;" fullword ascii
    $s20 = "contentDocument = Deferred;" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}