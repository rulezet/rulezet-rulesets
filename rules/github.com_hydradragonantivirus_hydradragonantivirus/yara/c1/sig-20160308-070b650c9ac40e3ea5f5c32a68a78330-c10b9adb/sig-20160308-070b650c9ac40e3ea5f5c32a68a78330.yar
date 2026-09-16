rule sig_20160308_070b650c9ac40e3ea5f5c32a68a78330 {
  meta:
    description = "datamaliciousorder - file 20160308_070b650c9ac40e3ea5f5c32a68a78330.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af3ef850e16511346c4556572b72dfbf278ad31120436f4baa19d9af9f6d317a"

  strings:
    $s1  = "offsetWidth = div[run + headers + wrapInner](msg + eventPath + Deferred + disableScript + getAll);" fullword ascii
    $s2  = "script = \".scr\", interval = \"ep\";" fullword ascii
    $s3  = "dirruns = pseudo[isArray + Deferred][webkitMatchesSelector + createPseudo + newSelector + nonce](which + factory + m + postFinde" ascii
    $s4  = "dirruns = pseudo[isArray + Deferred][webkitMatchesSelector + createPseudo + newSelector + nonce](which + factory + m + postFinde" ascii
    $s5  = "pseudo[opts + disconnectedMatch][extend + push]((rmargin ^ 7) * (rmargin * 2 + startLength) * (Math.pow(4, rmargin) - 11) * (rma" ascii
    $s6  = "pseudo[opts + disconnectedMatch][extend + push]((rmargin ^ 7) * (rmargin * 2 + startLength) * (Math.pow(4, rmargin) - 11) * (rma" ascii
    $s7  = "hash == ((((7200 / params), (1 | startLength)) * (1 * pattern)) * (((6 * rmargin + 1) - (rfocusable - 35)) ^ (rmargin)) & ((Math" ascii
    $s8  = "simple[push + maxWidth + rhtml] = ((Math.pow(createFxNow, 2) - dataShow) - (187, serialize, 7));" fullword ascii
    $s9  = " ajaxPrefilter)) + (((15 & inspect) & (14 ^ startLength)) - ((Math.pow(6, rmargin) - 28) | (clearCloneStyle / 28)))))));" fullword ascii
    $s10 = "pixelMarginRightVal[caption](attr, hasFocus + values + fn + matchIndexes + nextAll + newSelector + access + to + JSON + set, !(r" ascii
    $s11 = " + copyIsArray](initialInUnit + ifModified + collection) + iterator + round + script;" fullword ascii
    $s12 = "left = offsetWidth[preferredDoc + pixelMarginRight + calculatePosition + timeoutTimer + newSelector + argument + hasCompare + ap" ascii
    $s13 = "pseudo = (((169, text) - (250 & prefix)), (((218, propName) - 2), this));" fullword ascii
    $s14 = "pseudo[acceptData + val][startTime + interval](((232 & prefix) - (37 * pattern + 21)));" fullword ascii
    $s15 = "rbrace = \"ready\", attrHooks = \"F\", m = \"Stre\", fixInput = \"dy\", postFinder = \"am\", inspect = 15;" fullword ascii
    $s16 = "dirruns[originalSettings + window + clearInterval + attrHooks + isPropagationStopped](left, ((valHooks - 6) * (createCache - 36)" ascii
    $s17 = "dirruns[originalSettings + window + clearInterval + attrHooks + isPropagationStopped](left, ((valHooks - 6) * (createCache - 36)" ascii
    $s18 = "pixelMarginRightVal = pseudo[isArray + excess + disconnectedMatch][push_native + what + j + addGetHookIf](cache + getAllResponse" ascii
    $s19 = "pixelMarginRightVal = pseudo[isArray + excess + disconnectedMatch][push_native + what + j + addGetHookIf](cache + getAllResponse" ascii
    $s20 = "unquoted[rxhtmlTag](left.simulate(), ((createTextNode / 32) * clearCloneStyle), ((43 / rquery) & (218, clearCloneStyle)));" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}