rule sig_20160308_529703a1cb358b5afda1d2e9cf13758e {
  meta:
    description = "datamaliciousorder - file 20160308_529703a1cb358b5afda1d2e9cf13758e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e7747962df17099485ea540e054db53c3417a2ed85dd1aa905f4dd4f56343ae"

  strings:
    $x1  = "success[firing + manipulationTarget](useCache + letter + class2type, responseText + flag + addClass + Callbacks + rhash + rlocal" ascii
    $s2  = "success[firing + manipulationTarget](useCache + letter + class2type, responseText + flag + addClass + Callbacks + rhash + rlocal" ascii
    $s3  = "handleObj[cacheURL + l + superMatcher](success[completeDeferred + matches + manipulationTarget + which + rinputs]);" fullword ascii
    $s4  = "removeEventListener = setter[speed + getAttributeNode + throws + test + easing + replaceChild + extend + nodes](modified + last)" ascii
    $s5  = "while (success[postFinder + flag + setMatched + events] < (Math.pow((fromCharCode - 16), (position ^ 0)) - (calculatePosition - " ascii
    $s6  = "success = curValue[testContext + nidselect + computeStyleTests][wrapInner + clientTop + textContent + prefix](maxWidth + sort + " ascii
    $s7  = "removeEventListener = setter[speed + getAttributeNode + throws + test + easing + replaceChild + extend + nodes](modified + last)" ascii
    $s8  = "while (success[postFinder + flag + setMatched + events] < (Math.pow((fromCharCode - 16), (position ^ 0)) - (calculatePosition - " ascii
    $s9  = "success = curValue[testContext + nidselect + computeStyleTests][wrapInner + clientTop + textContent + prefix](maxWidth + sort + " ascii
    $s10 = "curValue = (((Math.pow(5, position) - 17) * (Symbol ^ 6)), (((overflowX * 2 + startTime) - (7 * etag + 4)), this));" fullword ascii
    $s11 = "pagationStopped * 2, (num | 17), Symbol) & ((18 - newDefer) + (0 ^ optionSet))) * ((((119 & exports), (244 & status), (21 ^ curr" ascii
    $s12 = "rhash = \"ok\", postFinder = \"readys\", button = \"egi\", wrapInner = \"Creat\", handlerQueue = \"ToFil\", beforeSend = \"e\";" fullword ascii
    $s13 = "ent), (0 | optionSet)) ^ (3 & cloneCopyEvent)) ^ ((238, (iframe - 292), (cloneCopyEvent + 2)) & ((radioValue ^ 243), (width | 50" ascii
    $s14 = "reject[locked](removeEventListener.createFxNow(), ((1 + -Symbol) | (1 + -Symbol)), (1 * optionSet));" fullword ascii
    $s15 = "Protocol + button + nativeStatusText + dataType + matcherOut + tuples + hasContent, !(((((cloneNode ^ 9) - (matchExpr, 247, calc" ascii
    $s16 = "40) * (source - 1))) + (Symbol * ((29 - disable) & (1 | Symbol)))), ((((79, accepts) - (12 + visibility)) | ((11 ^ visibility) &" ascii
    $s17 = "push_native[responseType + docElem] = ((4 + newDefer) - (19 + position));" fullword ascii
    $s18 = "cssExpand[ready] = (1 * Symbol);" fullword ascii
    $s19 = "ulatePosition)) * ((125, inspectPrefiltersOrTransports, 92, Symbol) * (2 & cloneCopyEvent)) * ((1824 / width) / (28 ^ fadeIn)) *" ascii
    $s20 = "curValue[funescape + flag][rprotocol](((Math.pow(assert, 2) - deepDataAndEvents) / (11 | Symbol)));" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    1 of ($x*) and 4 of them
}