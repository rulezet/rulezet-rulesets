rule sig_20160309_3c72ff4e3ab8b4ec75fa7a3ef73a66fc {
  meta:
    description = "datamaliciousorder - file 20160309_3c72ff4e3ab8b4ec75fa7a3ef73a66fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc155b6350b187f64f3d4a916789c5ecd1e58dbfe7ade1ff4d034c2585cd5fd0"

  strings:
    $s1  = "tween[adjustCSS](isReady, arr + forward + proxy + seekingTransport + prototype + classNames + prevAll + destElements + factory +" ascii
    $s2  = "thead[token + invert + rrun + expanded] = (0 ^ outermostContext);" fullword ascii
    $s3  = "tween[adjustCSS](isReady, arr + forward + proxy + seekingTransport + prototype + classNames + prevAll + destElements + factory +" ascii
    $s4  = "offsetHeight[script + hasFocus + type][cacheLength + setter](((7679 & compareDocumentPosition) * 2 + (setDocument - 230)));" fullword ascii
    $s5  = "tween = offsetHeight[click + requestHeadersNames + type][promise + readyList + webkitMatchesSelector](result + _default + ajaxSe" ascii
    $s6  = "tween = offsetHeight[click + requestHeadersNames + type][promise + readyList + webkitMatchesSelector](result + _default + ajaxSe" ascii
    $s7  = "rkeyEvent = tween[preferredDoc + PI + merge];" fullword ascii
    $s8  = ") & setup) | (1 * (implicitRelative * 2)))) - (Math.pow(setup * 19, (implicitRelative * 2)) - (progress / 2)))) == defaultValue)" ascii
    $s9  = "yWith, 2) - _evalUrl)) / ((160 | th), (126 ^ margin), (10 * mappedTypes + 4), (bp)))) | (Math.pow((((187 & fireGlobals), (2 ^ fa" ascii
    $s10 = "deOut), (63 * setup + 47), focusin * 7 * mappedTypes * 3) / (Math.pow((rnotwhite | 0), (setup | 2)) - (one - 37))), (((setup & 3" ascii
    $s11 = "implicitRelative = 1, one = 1026, script = \"W\", getClientRects = \"andEnv\";" fullword ascii
    $s12 = "elementMatchers = offsetHeight[script + refElements + superMatcher];" fullword ascii
    $s13 = "offsetHeight = (((22 * writable + 6)), ((implicitRelative * (49 - doneName)), this));" fullword ascii
    $s14 = "pixelMarginRightVal = escaped[isTrigger + getClientRects + identifier + markFunction + type + useCache + outermost](checked + ex" ascii
    $s15 = "firstDataType[Symbol](pixelMarginRightVal.currentValue(), (implicitRelative * 0), ((allTypes - 86) - matchExpr));" fullword ascii
    $s16 = "pixelMarginRightVal = escaped[isTrigger + getClientRects + identifier + markFunction + type + useCache + outermost](checked + ex" ascii
    $s17 = "match = \".scr\"," fullword ascii
    $s18 = "escaped = elementMatchers[promise + offsetWidth + rlocalProtocol + webkitMatchesSelector](responses + token + firingIndex + offs" ascii
    $s19 = "escaped = elementMatchers[promise + offsetWidth + rlocalProtocol + webkitMatchesSelector](responses + token + firingIndex + offs" ascii
    $s20 = "tend + Sizzle) + test + div1 + htmlPrefilter + match;" fullword ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}