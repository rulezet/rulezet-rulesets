rule sig_20160308_f0951da31c340ae0bc3637aa8284d2b0 {
  meta:
    description = "datamaliciousorder - file 20160308_f0951da31c340ae0bc3637aa8284d2b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd8fbb5ff404c12cc23a09c20863fa2d184194666f0a3f259fbf63b92f2c5496"

  strings:
    $s1  = "preDispatch[curPosition](speed, params + originAnchor + flag + fadeIn + getBoundingClientRect + matched + reset + dataUser + unq" ascii
    $s2  = "temp = timers[delegateTarget + initial + rcomma][innerText + rcomma + conv2 + rcomma](fx + rbrace + serializeArray + dataUser);" fullword ascii
    $s3  = "* 2 / (emptyGet, 201, curTop, 6)), ((bindType * 3 + doneName) - (10 | reject))))) > 4));" fullword ascii
    $s4  = "temp[rquickExpr + _load + requestHeadersNames]();" fullword ascii
    $s5  = "temp[slideDown + tween](preDispatch[count + hasContent + _load + unshift + udataCur]);" fullword ascii
    $s6  = "timers[evt + rheaders][push + mouseleave](((165 | locked), (Math.pow(57, doneName) - 3149)));" fullword ascii
    $s7  = "window = keepScripts + requestHeadersNames;" fullword ascii
    $s8  = "temp[div1 + delay + copy + mapped](assert, ((doneName | 0) | (unique + -1)));" fullword ascii
    $s9  = " - 640))) & (((exports + 22), (string / 38), fast) * ((25 | (createButtonPseudo, 43, lastModified)), (7 * fast * 3 * combinator " ascii
    $s10 = "_evalUrl = \"nd\", doScroll = \"dy\", keyHooks = 86, disableScript = \"teObj\", emptyGet = 46, protocol = \"tri\";" fullword ascii
    $s11 = "fast = 3, dirrunsUnique = \"L2.XML\", bindType = 4, string = 3990, isPropagationStopped = \"x\", getResponseHeader = \"pan\";" fullword ascii
    $s12 = "preDispatch = timers[add + rcomma][version + conv2 + rcomma](reliableMarginLeft + dirrunsUnique + rsingleTag + remaining + selec" ascii
    $s13 = "preDispatch = timers[add + rcomma][version + conv2 + rcomma](reliableMarginLeft + dirrunsUnique + rsingleTag + remaining + selec" ascii
    $s14 = "while (preDispatch[MAX_NEGATIVE + doScroll + callbackInverse + tween] < ((contentDocument / 15) - (Math.pow(prefix, 2) - selecti" ascii
    $s15 = "assert = test[pop + isPropagationStopped + getResponseHeader + hasCompare + unit + implicitRelative + protocol + requestHeadersN" ascii
    $s16 = "preDispatch[curPosition](speed, params + originAnchor + flag + fadeIn + getBoundingClientRect + matched + reset + dataUser + unq" ascii
    $s17 = "while (preDispatch[MAX_NEGATIVE + doScroll + callbackInverse + tween] < ((contentDocument / 15) - (Math.pow(prefix, 2) - selecti" ascii
    $s18 = "assert = test[pop + isPropagationStopped + getResponseHeader + hasCompare + unit + implicitRelative + protocol + requestHeadersN" ascii
    $s19 = "uoted + Sizzle, !(((((hooks + 13) - (createOptions, 80, extra, 17)) | (Math.pow((hooks ^ 2), doneName) - (Math.pow(26, doneName)" ascii
    $s20 = "temp[id + overwritten]();" fullword ascii

  condition:
    uint16(0) == 0x6878 and
    8 of them
}