rule sig_20160308_49a107929b6dfa400f8b5d3c5ce5b593 {
  meta:
    description = "datamaliciousorder - file 20160308_49a107929b6dfa400f8b5d3c5ce5b593.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8277243a9d34e7ace9a218f8c41090189e2e784f76624b90285f6ab9144d273"

  strings:
    $x1  = "progressValues[source](image, oldCache + rnative + byElement + sortOrder + oldCache + hasOwn + lock + domManip + letter + tick, " ascii
    $s2  = "one[attachEvent](progressValues[doc + operator + round + keepScripts + addEventListener]);" fullword ascii
    $s3  = "!((((((password - 29) * (compilerCache ^ 2) + (Math.pow(styles, 2) - winnow)) - ((72 ^ fn) | (28 & j))) * (((170, rfocusable), 4" ascii
    $s4  = "pipe = \"ect\", filters = \"L\", keepScripts = \"eBo\", processData = 41;" fullword ascii
    $s5  = "while(progressValues[init + getter + evt] < ((1 + -optDisabled), (4 & excess))) {" fullword ascii
    $s6  = "one = marginDiv[isFunction + fixHooks + isTrigger][removeClass + startLength + pipe](vendorPropName + getElementById + cssNumber" ascii
    $s7  = "one = marginDiv[isFunction + fixHooks + isTrigger][removeClass + startLength + pipe](vendorPropName + getElementById + cssNumber" ascii
    $s8  = "}, \"ns\"), visibility = \"Ex\", includeWidth = \"%TEMP%\", rsubmitterTypes = 13064, set = 2, method = \"TP\";" fullword ascii
    $s9  = "marginDiv = ((Math.pow((191 & suffix), (76 / throws)) - (59539 - groups)), (((56 * set + 37), (j, 0)), this));" fullword ascii
    $s10 = "progressValues = marginDiv[mouseleave + rnative][list + pageY + holdReady + rnative](rbuggyQSA + filters + combinator + maxWidth" ascii
    $s11 = "nodeType = createDocumentFragment[visibility + i + pos + hasData + rbracket + evt + pos + traditional + hasFocus](includeWidth +" ascii
    $s12 = "progressValues = marginDiv[mouseleave + rnative][list + pageY + holdReady + rnative](rbuggyQSA + filters + combinator + maxWidth" ascii
    $s13 = " keys) + parsed + parseFromString + bindType + types + fnOver + specialEasing + abort;" fullword ascii
    $s14 = "createDocumentFragment = original[funcName + prevAll + getAllResponseHeaders + rnative](originalProperties + parentOffset + xhrF" ascii
    $s15 = "createDocumentFragment = original[funcName + prevAll + getAllResponseHeaders + rnative](originalProperties + parentOffset + xhrF" ascii
    $s16 = "one[delay + setFilters + PI](nodeType, ((currentTime - 22) ^ (returnValue & 3)));" fullword ascii
    $s17 = "   marginDiv[originalProperties + specified + slow][mappedTypes + maxIterations](((220 & ct), (9675 / dataPriv), (75 - getAttrib" ascii
    $s18 = "   marginDiv[originalProperties + specified + slow][mappedTypes + maxIterations](((220 & ct), (9675 / dataPriv), (75 - getAttrib" ascii
    $s19 = "password = 84;" fullword ascii
    $s20 = "var getter = \"ystat\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}