rule sig_20160308_271b61b65f625247f42bad9343eb4433 {
  meta:
    description = "datamaliciousorder - file 20160308_271b61b65f625247f42bad9343eb4433.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ea92392207bebf83d858f01ec84fef742d2961d913e1a5ab85f17e2a51544ab"

  strings:
    $s1  = "proxy = err[handleObjIn + getClass + superMatcher][destElements + curPosition + sortStable + password + superMatcher](throws + p" ascii
    $s2  = "adjusted[fireGlobals](radio, inspected + superMatcher + superMatcher + urlAnchor + guaranteedUnique + rnative + hide + fnOut + r" ascii
    $s3  = "adjusted = err[scriptCharset + responseHeaders][noConflict + isLocal + after](reliableMarginLeftVal + token + current + elems + " ascii
    $s4  = "adjusted = err[scriptCharset + responseHeaders][noConflict + isLocal + after](reliableMarginLeftVal + token + current + elems + " ascii
    $s5  = "proxy = err[handleObjIn + getClass + superMatcher][destElements + curPosition + sortStable + password + superMatcher](throws + p" ascii
    $s6  = "err[contexts + a + superMatcher][combinator](((24213 ^ push) - 13 * qsaError * 211));" fullword ascii
    $s7  = "parseOnly = parentNode[stopImmediatePropagation + xhr + removeProp + caption + self](location + getAll) + readyWait + rfocusable" ascii
    $s8  = "err = (((197, matcherFromGroupMatchers, 86), (width ^ 160), container * 2 * key, (3 ^ maxIterations)), (((334 - bySet), (2 | max" ascii
    $s9  = "err = (((197, matcherFromGroupMatchers, 86), (width ^ 160), container * 2 * key, (3 ^ maxIterations)), (((334 - bySet), (2 | max" ascii
    $s10 = "arseHTML + wrap + disableScript);" fullword ascii
    $s11 = "esults + hasFocus, !((Math.pow((((21 | global) ^ (20 + rtypenamespace)), ((86 ^ document) ^ (23 * qsaError + 6)), ((removeEventL" ascii
    $s12 = "password = \"bjec\";" fullword ascii
    $s13 = "parseOnly = parentNode[stopImmediatePropagation + xhr + removeProp + caption + self](location + getAll) + readyWait + rfocusable" ascii
    $s14 = "ns) / (0 ^ backgroundClip))) * (((1 + -backgroundClip) | 2) * ((handler - 45) ^ (acceptData | 28)) - (((mouseHooks | 470) + isSi" ascii
    $s15 = "    err[handleObjIn + getClass + superMatcher][adjustCSS + documentElement]((Math.pow(31 * pushStack, (1 * pushStack)) - (672 | " ascii
    $s16 = "parentNode = disconnectedMatch[stopPropagation + unique + propFix + after](readyList + slow + eased + attr);" fullword ascii
    $s17 = "proxy[matchAnyContext + rfocusable]();" fullword ascii
    $s18 = "disconnectedMatch = err[readyList + slow + superMatcher];" fullword ascii
    $s19 = "proxy[step](adjusted[nodeValue + checkDisplay + createInputPseudo]);" fullword ascii
    $s20 = "while (adjusted[src + ajaxHandleResponses + letterSpacing + rfocusable] < (qsaError & (0 | originalEvent))) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}