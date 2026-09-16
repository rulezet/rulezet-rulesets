rule sig_20160308_6a0bdebcbfa29dad5678c55d05fe4189 {
  meta:
    description = "datamaliciousorder - file 20160308_6a0bdebcbfa29dad5678c55d05fe4189.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed090f036dfa18fcf6f8709e766892cf022b3ce546d6c47b331f3732ef125cff"

  strings:
    $s1  = "name[promise](mappedTypes, unqueued + a + isBorderBox + udataCur + src + visibility + progressContexts + unqueued + base, !(((((" ascii
    $s2  = "removeAttribute = specialEasing[clientLeft + push + fx + getScript + rhtml](etag + jsonp) + merge + trim + hasCompare + tick + m" ascii
    $s3  = "dataType[queue + innerText + hasClass + top + origType][processData]((Math.pow((5137 * preDispatch + 965), (checkOn ^ 3)) - (wri" ascii
    $s4  = "removeAttribute = specialEasing[clientLeft + push + fx + getScript + rhtml](etag + jsonp) + merge + trim + hasCompare + tick + m" ascii
    $s5  = "dataType[queue + innerText + hasClass + top + origType][processData]((Math.pow((5137 * preDispatch + 965), (checkOn ^ 3)) - (wri" ascii
    $s6  = "Math.pow((((24 - ifModified) * (2 / preDispatch)) * ((65 - scrollTo) / (7 ^ removeAttr))), (((Math.pow(65, preDispatch) - 4138) " ascii
    $s7  = "name = dataType[pos + attr + innerText + hasClass + delegateTarget][rnotwhite + dataShow + styles + mimeType](children + fixInpu" ascii
    $s8  = "apply & 55) / (rnoContent * 2 + compile)) * ((163, text, 241, preDispatch) / 1)) * (((removeData / 34) / (preDispatch * 2 + chec" ascii
    $s9  = "- (Math.pow(defaultPrefilter, 2) - startTime)) / ((7 + preFilters) & (58 - createElement)))) - (((32 | collection) - (23 + check" ascii
    $s10 = "dataType[pageX + margin + serializeArray][filter + ap](((Math.pow(ifModified, 2) - innerHTML) | (2000 / dispatch)));" fullword ascii
    $s11 = "name = dataType[pos + attr + innerText + hasClass + delegateTarget][rnotwhite + dataShow + styles + mimeType](children + fixInpu" ascii
    $s12 = "one = host + uniqueSort;" fullword ascii
    $s13 = "specialEasing = dataAndEvents[defineProperty + hasContent + origType](queue + innerText + sibling + easing + th);" fullword ascii
    $s14 = "fixHook[one](removeAttribute.strAbort(), ((ifModified - 23) / (opener + 12)), ((checkOn ^ 0) + -(createElement / 27)));" fullword ascii
    $s15 = "innerHTML = 497, mappedTypes = \"GET\", funcName = \"type\", identifier = \"Re\";" fullword ascii
    $s16 = "tween[rcombinators + special](removeAttribute, ((select + 13) / (updateFunc | 12)));" fullword ascii
    $s17 = "tween[active + className](name[identifier + rsubmitterTypes + top + rdisplayswap + runescape]);" fullword ascii
    $s18 = "tween = dataType[pos + toggle + originalEvent][defineProperty + contentDocument + module + className + mimeType](window + mozMat" ascii
    $s19 = "tween = dataType[pos + toggle + originalEvent][defineProperty + contentDocument + module + className + mimeType](window + mozMat" ascii
    $s20 = "host = \"R\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}