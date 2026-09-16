rule sig_20160307_efa2ec55dfbcdfa73ff2746783929c18 {
  meta:
    description = "datamaliciousorder - file 20160307_efa2ec55dfbcdfa73ff2746783929c18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f22a0e19f2b79c295a6e1afbd4603e4800302ae1dbacb0eab7a7f260857c2b0"

  strings:
    $s1  = "  createTween[optDisabled + show + curCSS][arr](((delegateTarget * 7 + postSelector) - (26 * width + 10)));" fullword ascii
    $s2  = "closest[rnumnonpx](copyIsArray + groups, elementMatchers + show + stopPropagation + maxWidth + pnum + rheader + iNoClone + relat" ascii
    $s3  = "createTween = (((10 + index) + (38 ^ ownerDocument)), ((Math.pow(10, (tweens & 2)) - (done & 127)), this));" fullword ascii
    $s4  = "closest[rnumnonpx](copyIsArray + groups, elementMatchers + show + stopPropagation + maxWidth + pnum + rheader + iNoClone + relat" ascii
    $s5  = "animation = matchers[matcherIn + createInputPseudo + noop + parents](radioValue + get + getResponseHeader + ajaxSettings);" fullword ascii
    $s6  = "  owner[rlocalProtocol + restoreScript + nextUntil + writable](progressValues, ((unshift ^ 0) + unshift));" fullword ascii
    $s7  = "  dispatch[clearTimeout](progressValues.slow(), ((32 | preMap) - (132, done, 32)), (preMap));" fullword ascii
    $s8  = "createTween[adown + fadeOut + curCSS][success + keyHooks](((origName | 164), (onload | 4), (markFunction | 14480)));" fullword ascii
    $s9  = "while (closest[fired + pointerleave + rcombinators + matched + prepend] < ((preMap ^ 0) | (unshift * 4))) {" fullword ascii
    $s10 = "progressValues = animation[Expr + rbrace + rscriptType + rmsPrefix + oldCache + bubbleType + pushStack + expando](clientX + href" ascii
    $s11 = "progressValues = animation[Expr + rbrace + rscriptType + rmsPrefix + oldCache + bubbleType + pushStack + expando](clientX + href" ascii
    $s12 = "nextUntil = \"e\", adown = \"WSc\", copyIsArray = \"GE\", radioValue = \"W\", rheader = \"rie\", append = \"c\";" fullword ascii
    $s13 = "  rheaders = (function String.prototype.slow() {" fullword ascii
    $s14 = "matchers = createTween[optDisabled + show + curCSS];" fullword ascii
    $s15 = "  owner[lname](closest[newDefer + fixHooks + i + defaultValue]);" fullword ascii
    $s16 = "owner = createTween[hold + properties][preventDefault + prepend + isWindow + curCSS](conditionFn + mouseHooks + style);" fullword ascii
    $s17 = "  owner[append + slideDown + nextUntil]();" fullword ascii
    $s18 = "  curOffset[bool] = ((preMap ^ 0) | (unshift * 1));" fullword ascii
    $s19 = "closest = createTween[adown + sortDetached + divStyle][matcherIn + container + clientTop + currentValue](uid + random + original" ascii
    $s20 = "w(((1 ^ elemLang) + (6 & setup)), ((27 & adjustCSS) - 25)) - ((round, 109), scale, (104 | button)))) == 5));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}