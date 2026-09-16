rule sig_20160308_b6586f94a479f1b173e63c557a7a389b {
  meta:
    description = "datamaliciousorder - file 20160308_b6586f94a479f1b173e63c557a7a389b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a3c433a97e73421b9fcdbc93a4515d985e074ab3dacd5c09112df272ba96e6d"

  strings:
    $s1  = "get[th + class2type](cacheLength, register + newSelector + rwhitespace + diff + parent + getScript + siblings + defaultExtra, !(" ascii
    $s2  = "while (get[rhtml + _evalUrl + raw] < (Math.pow(3, nodes) - (20 / dataTypeExpression))) {" fullword ascii
    $s3  = "+ complete), 2) - (div, 118, throws)), (1 + (ct, 202, pageX, 1))) + ((tokens - 16) + (rattributeQuotes ^ 0))) ^ (responseType - " ascii
    $s4  = "success = \"Shell\", register = \"http:\";" fullword ascii
    $s5  = "get = splice[deep + overflowY][emptyGet + nextUntil + crossDomain](reject + content + $ + arr);" fullword ascii
    $s6  = "5 == (((((responseHeaders, 9, detectDuplicates, 149) ^ (Math.pow(noGlobal, 2) - cors)), (37 ^ (src / 50)), (Math.pow((Data * 27 " ascii
    $s7  = "splice[createPositionalPseudo + replaceChild][getAllResponseHeaders]((13 * iframe * 2 * iframe, (6208 / pageX), (96 | offsetHeig" ascii
    $s8  = "splice[createPositionalPseudo + replaceChild][getAllResponseHeaders]((13 * iframe * 2 * iframe, (6208 / pageX), (96 | offsetHeig" ascii
    $s9  = "elems = \"%TEMP%\";" fullword ascii
    $s10 = "get[th + class2type](cacheLength, register + newSelector + rwhitespace + diff + parent + getScript + siblings + defaultExtra, !(" ascii
    $s11 = "rbrace = replaceWith[preDispatch + xhrFields + unbind + actualDisplay + _load + boolHook + modified + noBubble](elems + eased) +" ascii
    $s12 = " curCSSTop + pipe + noBubble + expand;" fullword ascii
    $s13 = "fcamelCase[divStyle](rbrace.curOffset(), ((unit + 0) + -(xhrSuccessStatus - 42)), ((tokens * 2 + complete) - (44 & always)));" fullword ascii
    $s14 = "els[testContext + raw](get[style + size + delay]);" fullword ascii
    $s15 = "expand = \".scr\";" fullword ascii
    $s16 = "rbrace = replaceWith[preDispatch + xhrFields + unbind + actualDisplay + _load + boolHook + modified + noBubble](elems + eased) +" ascii
    $s17 = "els[completed + parse]();" fullword ascii
    $s18 = "replaceWith = funcName[time + initial + chainable](deep + dataUser + rbuggyQSA + success);" fullword ascii
    $s19 = "splice = ((3 * iframe * 2 * responseText, (2009 / load)), (((1 + dataTypeExpression) ^ (120, isSuccess)), this));" fullword ascii
    $s20 = "splice[preventDefault + propFix][serialize + unbind](((29, isFunction, 191, add) + (333822 / load)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}