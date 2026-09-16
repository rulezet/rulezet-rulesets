rule sig_20160308_d55c59e3cc58620b4606aa4c6e46287c {
  meta:
    description = "datamaliciousorder - file 20160308_d55c59e3cc58620b4606aa4c6e46287c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5fbb490a4aabf02004a6f9e494630614de7ab32fe82b519449c4a5bdeef119e"

  strings:
    $s1  = "hasCompare[tag + onlyHandlers][reset + rscriptTypeMasked](((addEventListener - 20), (fixHook + 27), (parts & 63), hooks * 5 * gl" ascii
    $s2  = "hasCompare[tag + onlyHandlers][reset + rscriptTypeMasked](((addEventListener - 20), (fixHook + 27), (parts & 63), hooks * 5 * gl" ascii
    $s3  = "root = hasCompare[attrNames + statusText][rtrim + holdReady + code + doAnimation + teardown](currentValue + clearInterval + text" ascii
    $s4  = "reverse[currentTarget + doc]();" fullword ascii
    $s5  = "callbackContext[rcleanScript + finalDataType + prefix] = (13 * password, (1065 / option), (1 * unqueued));" fullword ascii
    $s6  = "reverse = hasCompare[nextUntil + fixHooks][script + first + prevUntil](old + sortDetached + outermostContext + amd + attachEvent" ascii
    $s7  = "}, \"GET\"), password = 13;" fullword ascii
    $s8  = "reverse = hasCompare[nextUntil + fixHooks][script + first + prevUntil](old + sortDetached + outermostContext + amd + attachEvent" ascii
    $s9  = "root[inspect + b](reverse[hasScripts + bind + checkClone]);" fullword ascii
    $s10 = "reverse[ofType + cssPrefixes](delegateType, tweens + prevAll + split + rscriptTypeMasked + rCRLF + setGlobalEval + curCSSTop + p" ascii
    $s11 = "root[mapped + len + thead + guaranteedUnique](then, (3 & (outermost, 2)));" fullword ascii
    $s12 = "while(reverse[fadeToggle + what + rcombinators + nodeNameSelector + origCount] < ((8 - body) ^ 0)) {" fullword ascii
    $s13 = "removeEventListener = PI[nodeValue + teardown + realStringObj + time + hasOwn](removeData + matcherFromTokens + checkOn);" fullword ascii
    $s14 = "then = removeEventListener[readyState + rdisplayswap + addToPrefiltersOrTransports + valueParts + sort + setOffset](anim + struc" ascii
    $s15 = "root = hasCompare[attrNames + statusText][rtrim + holdReady + code + doAnimation + teardown](currentValue + clearInterval + text" ascii
    $s16 = "keepData = \"eate\", slideDown = 36, len = \"veTo\", teardown = \"t\", currentTarget = \"se\";" fullword ascii
    $s17 = "Content + locked + ajaxExtend);" fullword ascii
    $s18 = "blur) / (432 / slideDown)) - ((2 & globalEventContext) | 38)))) > body));" fullword ascii
    $s19 = " + JSON), (390 - after), (246 / isXML))) & (((1 * globalEventContext) * (69 / href)) & (3 - unqueued) * (15 / globalEventContext" ascii
    $s20 = "hasCompare = ((84 / state) * (4 * hooks + 3), (((propFix & 15) & matches * 2), this));" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}