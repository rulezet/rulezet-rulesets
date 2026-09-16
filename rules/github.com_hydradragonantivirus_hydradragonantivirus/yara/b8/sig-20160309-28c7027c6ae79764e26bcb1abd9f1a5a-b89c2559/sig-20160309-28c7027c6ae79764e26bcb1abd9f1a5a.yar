rule sig_20160309_28c7027c6ae79764e26bcb1abd9f1a5a {
  meta:
    description = "datamaliciousorder - file 20160309_28c7027c6ae79764e26bcb1abd9f1a5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3c3624d049c0f53594c55f2fc9ef0659de92ad24a42b9d94589ace914c9027e"

  strings:
    $s1  = "andSelf[gotoEnd + easing](blur, buildParams + rscriptType + webkitMatchesSelector + propHooks + once + tokenCache + duration + w" ascii
    $s2  = "nativeStatusText = defaultExtra[textContent + fadeOut + Symbol + keyCode](username + defaultDisplay + el + onreadystatechange + " ascii
    $s3  = "nativeStatusText = defaultExtra[textContent + fadeOut + Symbol + keyCode](username + defaultDisplay + el + onreadystatechange + " ascii
    $s4  = "curCSSLeft[matches + prop] = ((Math.pow(completed, 2) - condense) - 2 * cssExpand * 2 * tweeners * 2);" fullword ascii
    $s5  = "etAttributeNode) + 16) - ((Math.pow(filter, 2) - module) & (40 | next)))) * (((1 * (rjsonp ^ 1)) & (ready | 1)) + ((rjsonp | 1) " ascii
    $s6  = "to = (((357 / bool) + (1924 / contentType)), (((25 ^ global) - 7 * cssExpand * 2 * cssExpand), this));" fullword ascii
    $s7  = "andSelf = to[divStyle + overwritten][curTop + anim + speeds + htmlPrefilter + s](match + dataTypeOrTransport + isArray + compare" ascii
    $s8  = "pow(24, cssExpand) - 547)), ready))) == 9));" fullword ascii
    $s9  = "keepData[insertAfter + transport](xhrFields, ((rjsonp | 18) - (rjsonp | 16)));" fullword ascii
    $s10 = "+ ((filter * 2 + off) - (Math.pow(28, cssExpand) - 746)))) + ((((charset ^ 14) & (cos & 31)) - ((Math.pow(outermost, 2) - append" ascii
    $s11 = "t[detach](xhrFields.pseudo(), ((ready + -1) & ready), (0 / unmatched));" fullword ascii
    $s12 = "andSelf = to[divStyle + overwritten][curTop + anim + speeds + htmlPrefilter + s](match + dataTypeOrTransport + isArray + compare" ascii
    $s13 = "xhrFields = nativeStatusText[rdisplayswap + pnum + contexts + evt + button + value + removeEventListener](expanded + unshift) + " ascii
    $s14 = "keepData = to[username + s][until + rsingleTag + Symbol + keyCode](groups + init + pdataCur);" fullword ascii
    $s15 = "andSelf[gotoEnd + easing](blur, buildParams + rscriptType + webkitMatchesSelector + propHooks + once + tokenCache + duration + w" ascii
    $s16 = "needsContext + close + Symbol + rnumnonpx + rrun + contexts;" fullword ascii
    $s17 = "DocumentPosition + fail + tr + currentValue);" fullword ascii
    $s18 = "To) + (0 | ready))) & (((215, elementMatchers, 161, dataShow) * (67, xhr, 10) + (cssExpand ^ 14)), (display * (2 ^ off) + (Math." ascii
    $s19 = "xhrFields = nativeStatusText[rdisplayswap + pnum + contexts + evt + button + value + removeEventListener](expanded + unshift) + " ascii
    $s20 = "load = andSelf[cacheURL + ajaxConvert + elemData + getPropertyValue];" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}