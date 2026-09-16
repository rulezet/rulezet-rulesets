rule sig_20160308_5fc32a2ac4b0e1287d3ee5bfaadc3a57 {
  meta:
    description = "datamaliciousorder - file 20160308_5fc32a2ac4b0e1287d3ee5bfaadc3a57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3936e5ef5014209634409eb9d428a9a7819f6af1ce559b3288ec6dcc314ac5"

  strings:
    $s1  = "holdReady = colgroup[content + cssExpand][tuple + opts + getAllResponseHeaders](tabIndex + prepend + unqueued + rrun + contexts)" ascii
    $s2  = "holdReady = colgroup[content + cssExpand][tuple + opts + getAllResponseHeaders](tabIndex + prepend + unqueued + rrun + contexts)" ascii
    $s3  = "aultPrevented, 2) - list) ^ (Math.pow(79, matches) - 6130)), (complete / (304 / clientX))) ^ (1 + complete)) ^ (((0 ^ (complete " ascii
    $s4  = "err = rhash[ajax + option + rhtml + username + fadeToggle + defaultExtra + cur + addGetHookIf + indirect](load + nType + params)" ascii
    $s5  = "image[addGetHookIf + unbind] = (172, elementMatchers);" fullword ascii
    $s6  = "err = rhash[ajax + option + rhtml + username + fadeToggle + defaultExtra + cur + addGetHookIf + indirect](load + nType + params)" ascii
    $s7  = "w(createFxNow, 2) - conditionFn) - (148, rsibling, 78)), (Math.pow((left | 66), (matches + 0)) - (opt ^ 3732)), ((Math.pow(isDef" ascii
    $s8  = "arr[j](err.width(), ((insertAfter | 68), (complete | 0)), ((setMatchers, 1) * (outermostContext - 9)));" fullword ascii
    $s9  = "rhash = slow[tuple + beforeSend + fcamelCase + rclass](getElementsByClassName + cacheLength + Callbacks + readyState);" fullword ascii
    $s10 = "box[oldCallbacks](cssPrefixes, emptyStyle + rnoInnerhtml + init + module + marginRight + remove + finalText, !(1 == (((((Math.po" ascii
    $s11 = "timeout[disable + xhrSupported] = ((0 & complete) / (10 * fn));" fullword ascii
    $s12 = "box = colgroup[teardown + globalEventContext][needsContext + parseJSON + throws + addGetHookIf](bool + getBoundingClientRect + b" ascii
    $s13 = "colgroup[htmlPrefilter + callback + addGetHookIf][marginDiv + timeoutTimer](((delegateType - 24) * (pattern * 2 + pos)));" fullword ascii
    $s14 = "while (box[removeAttr + preexisting + maxIterations + fx] < matches * (173, getWindow, 2)) {" fullword ascii
    $s15 = "box = colgroup[teardown + globalEventContext][needsContext + parseJSON + throws + addGetHookIf](bool + getBoundingClientRect + b" ascii
    $s16 = "colgroup = (((3 & inArray) & (30 - setMatchers)), (((0 | checkDisplay) - (3 & inArray)), this));" fullword ascii
    $s17 = "^ 0)) | ((elementMatchers + 0) + complete)) * 0))));" fullword ascii
    $s18 = "delegateType = 29, load = \"%TEMP\", maxIterations = \"a\", using = \"en\", createHTMLDocument = \"lose\";" fullword ascii
    $s19 = "holdReady[count + using]();" fullword ascii
    $s20 = "holdReady[active + createHTMLDocument]();" fullword ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}