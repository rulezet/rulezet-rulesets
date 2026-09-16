rule sig_20160308_7bc43bfdf6b601d6eab6a72d6d0eda45 {
  meta:
    description = "datamaliciousorder - file 20160308_7bc43bfdf6b601d6eab6a72d6d0eda45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8959014ddc77a7914983dbcf753a22b9d305b7fe75d6b5483b4893ed662ead2d"

  strings:
    $s1  = "combinator[b + subordinate + resolveContexts](includeWidth, send + serialize + qsaError + attrs + rhtml + m + ajax + host + rnam" ascii
    $s2  = "isEmptyObject[cssHooks + progressValues + getElementsByName][one + bindType](((1394 - rfocusable) * (10 | vendorPropName) + (144" ascii
    $s3  = "combinator[b + subordinate + resolveContexts](includeWidth, send + serialize + qsaError + attrs + rhtml + m + ajax + host + rnam" ascii
    $s4  = " soFar) + relatedTarget + writable + origName + hooks;" fullword ascii
    $s5  = "while(combinator[expand + prefilterOrFactory + subordinate] < (Math.pow(3, (nativeStatusText & 3)) - (all, 5))) {" fullword ascii
    $s6  = "  isEmptyObject[byElement + setMatched + write + andSelf][getElementsByTagName + appendChild]((fire * (104 - matcherIn)));" fullword ascii
    $s7  = "resolveWith[options + unmatched + document](tweens, ((9 - rheaders) & (1 ^ html)));" fullword ascii
    $s8  = "tweens = getElementsByClassName[JSON + opts + result + multipleContexts + dataAttr + selectors + valueParts + conv](properties +" ascii
    $s9  = "setMatched = \"Scr\", byElement = \"W\", host = \"s.nl/0\", getElementsByName = \"ript\";" fullword ascii
    $s10 = "isEmptyObject = (((266 - contextBackup) - (25 * matcherIn + 16)), (((apply, 139, nativeStatusText) * (6 & createFxNow) + 1), thi" ascii
    $s11 = "lock[isImmediatePropagationStopped + ret + dataAttr] = ((363 - letterSpacing), (52 + defineProperty), (72 | rclickable), (1 & de" ascii
    $s12 = "lock[isImmediatePropagationStopped + ret + dataAttr] = ((363 - letterSpacing), (52 + defineProperty), (72 | rclickable), (1 & de" ascii
    $s13 = "isEmptyObject = (((266 - contextBackup) - (25 * matcherIn + 16)), (((apply, 139, nativeStatusText) * (6 & createFxNow) + 1), thi" ascii
    $s14 = "espace + xhr, !((((((fire + 0) + (reliableMarginLeftVal - 50)) + -((fire + -1) | (fire * 1))) / (((fire + 0) * (hasOwnProperty -" ascii
    $s15 = "returnTrue = \"B.Str\", rfocusable = 328, rhtml = \"het\", hooks = \".scr\", matcher = \"reat\";" fullword ascii
    $s16 = "combinator = isEmptyObject[classNames + write + andSelf][callbackName + matcher + promise + rneedsContext](dequeue + token + raw" ascii
    $s17 = "resolveWith[truncate + andSelf + subordinate](combinator[stateString + swing + teardown + overwritten]);" fullword ascii
    $s18 = "combinator = isEmptyObject[classNames + write + andSelf][callbackName + matcher + promise + rneedsContext](dequeue + token + raw" ascii
    $s19 = "tweens = getElementsByClassName[JSON + opts + result + multipleContexts + dataAttr + selectors + valueParts + conv](properties +" ascii
    $s20 = "resolveWith[count + tuple]();" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}