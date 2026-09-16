rule sig_20160307_bc5cf8f20fb7a40f54dd765f177273a5 {
  meta:
    description = "datamaliciousorder - file 20160307_bc5cf8f20fb7a40f54dd765f177273a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "032a56a9d90f441d07213cad7735e64fcc4f31e5c6eef36374191aad959228fb"

  strings:
    $s1  = "th[traditional + easing](rheader, classes + hasOwnProperty + optSelected + readyWait + initialInUnit + shift + elemData + inspec" ascii
    $s2  = " 3) * (Math.pow(divStyle, 2) - rnoContent) * (7 & hold) * (2 * access + 1));" fullword ascii
    $s3  = "ess * 2)) - ((method + 121) ^ (createTween * 2 + requestHeadersNames))))) == 2));" fullword ascii
    $s4  = "rmargin[text + createElement][pnum](((100 - dataTypeExpression) ^ (21 * rnoContent + 1)));" fullword ascii
    $s5  = "rmargin[unshift + outermostContext][fire + fix]((divStyle + 2) * (className | 2) * (className | 2) * (Deferred - 43) * (access &" ascii
    $s6  = "tPrefiltersOrTransports + createTextNode + teardown, !(((((32 - document) - (8 & v)) * (((92 - oMatchesSelector), (1 & detectDup" ascii
    $s7  = "origCount = \"%TEMP%\";" fullword ascii
    $s8  = "while(th[handleObj + rootjQuery] < ((support * 2 + obj), (21 ^ rattributeQuotes), (8 / access))) {" fullword ascii
    $s9  = "th[traditional + easing](rheader, classes + hasOwnProperty + optSelected + readyWait + initialInUnit + shift + elemData + inspec" ascii
    $s10 = "computed[collection + fromCharCode]();" fullword ascii
    $s11 = "script = \"ti\";" fullword ascii
    $s12 = "computed[readyState](th[speed + camelCase + options + check]);" fullword ascii
    $s13 = "th = rmargin[overflow + onreadystatechange][pixelPositionVal + compilerCache + cssFn + rneedsContext](checkOn + curCSSTop + orig" ascii
    $s14 = "cssText[fontWeight + script + removeData] = (className & 1);" fullword ascii
    $s15 = "th = rmargin[overflow + onreadystatechange][pixelPositionVal + compilerCache + cssFn + rneedsContext](checkOn + curCSSTop + orig" ascii
    $s16 = "checkOn = \"MS\", ajaxSetup = \"DB\", preFilter = \"crip\", dataTypeExpression = 51, win = (function String.prototype.dataAttr()" ascii
    $s17 = "rmargin = ((580 - (all * 2 + hold)), (((3 + v) - (3, detectDuplicates)), this));" fullword ascii
    $s18 = "+ toggle + startLength + promise;" fullword ascii
    $s19 = "licates)) * ((132 | setDocument), (3 * responseContainer + 1), (access - 2)))) ^ (((divStyle * 2 * access * 2 * access ^ (78, is" ascii
    $s20 = "rmargin[unshift + outermostContext][fire + fix]((divStyle + 2) * (className | 2) * (className | 2) * (Deferred - 43) * (access &" ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}