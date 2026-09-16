rule sig_20160308_7edc5957d506968771e03db6e63cf3ee {
  meta:
    description = "datamaliciousorder - file 20160308_7edc5957d506968771e03db6e63cf3ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2148906f4cdfb50b16512d75239662225cdfa3f97eafad2970b490db173f6c82"

  strings:
    $x1  = "rkeyEvent[matchIndexes](param + simulate, _data + setMatched + checkContext + undelegate + rcleanScript + responseHeaders + isEm" ascii
    $s2  = "rkeyEvent[matchIndexes](param + simulate, _data + setMatched + checkContext + undelegate + rcleanScript + responseHeaders + isEm" ascii
    $s3  = "getAllResponseHeaders[noop + send + parseOnly + defaultPrevented](udataCur, ((_ - 31) + (operator ^ 0)));" fullword ascii
    $s4  = "globalEventContext[attrHooks + swing] = ((0 | operator) / (Math.pow(6, dataFilter) - 29));" fullword ascii
    $s5  = "responseHeaders = \"im\", actualDisplay = 31, send = \"v\", operator = 0, rscriptTypeMasked = \"ep\", rnumnonpx = 9;" fullword ascii
    $s6  = "Math.pow((charset - 165), (cacheURL * 2)) - (groups - 4671))) - (((scrollLeft & 503) - (PI & 119)) / ((rnoContent - 60) + (Math." ascii
    $s7  = "getAllResponseHeaders = htmlPrefilter[value + source][defaultExtra + insertAfter + left + source](stopImmediatePropagation + uns" ascii
    $s8  = "rkeyEvent = htmlPrefilter[value + source][qualifier + isArray + leadingRelative + cur + before](raw + p + memory + defaultPrefil" ascii
    $s9  = "rkeyEvent = htmlPrefilter[value + source][qualifier + isArray + leadingRelative + cur + before](raw + p + memory + defaultPrefil" ascii
    $s10 = "== (((((492 & rsingleTag) / (55 - pos)) - ((754 / selectors) ^ (0 | next))) / (((Math.pow(59, dataFilter) - 3419) / (mouseHooks " ascii
    $s11 = "defaultPrefilter = \"L2.X\", timerId = \"rings\", _$ = \"%TEMP%\";" fullword ascii
    $s12 = "htmlPrefilter[value + source][statusText + firstElementChild]((Math.pow((101970 / rnumnonpx), (100 / funescape)) - (111804072 + " ascii
    $s13 = "htmlPrefilter[not + setPositiveNumber + nodeIndex][base + rscriptTypeMasked](((hasFocus) * (6 + dataFilter) + (152 / clearCloneS" ascii
    $s14 = "ptyObject + active, !((((Math.pow(((280 - qsaError), (Math.pow(124, dataFilter) - 15145), (slideDown - 59)), (cacheURL * 2)) - (" ascii
    $s15 = "htmlPrefilter[not + setPositiveNumber + nodeIndex][base + rscriptTypeMasked](((hasFocus) * (6 + dataFilter) + (152 / clearCloneS" ascii
    $s16 = "headers[s + firstElementChild + isArray] = ((0 | cacheURL) & (40 - always));" fullword ascii
    $s17 = "ret[hide](udataCur.replaceChild(), (operator ^ (1 * operator)), ((4 / preDispatch) + -(11 / cacheLength)));" fullword ascii
    $s18 = "getAllResponseHeaders = htmlPrefilter[value + source][defaultExtra + insertAfter + left + source](stopImmediatePropagation + uns" ascii
    $s19 = "hift + source + forward);" fullword ascii
    $s20 = "htmlPrefilter = (((152 ^ contentType), (74 + cacheLength), (4662 / run)), (((164 / pixelMarginRight) * (1 * preDispatch) + (1 & " ascii

  condition:
    uint16(0) == 0x6372 and
    1 of ($x*) and 4 of them
}