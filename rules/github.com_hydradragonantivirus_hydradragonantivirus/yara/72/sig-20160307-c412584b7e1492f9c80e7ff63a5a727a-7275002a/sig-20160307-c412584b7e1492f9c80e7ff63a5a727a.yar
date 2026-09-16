rule sig_20160307_c412584b7e1492f9c80e7ff63a5a727a {
  meta:
    description = "datamaliciousorder - file 20160307_c412584b7e1492f9c80e7ff63a5a727a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2683726838598995f4700c5a5e9021bd752db5069433f9bdba93bf65605cfa0"

  strings:
    $s1  = "noConflict = (((15 + tween) & (Math.pow(30, map) - 856)), (getAllResponseHeaders, this));" fullword ascii
    $s2  = "  duration[buildParams](setGlobalEval.file(), ((isSimulated ^ 0) + -(isSimulated & 1)), ((content - 4) * linear));" fullword ascii
    $s3  = "manipulationTarget = 3, subordinate = \"ell\";" fullword ascii
    $s4  = "props[ontype](rhash + curElem, remove + key + prevObject + append + toArray + grep + callbackContext + invert + elemdisplay + ar" ascii
    $s5  = "elem = parts[getWindow + relative + sibling](udataCur + rmsPrefix + subordinate);" fullword ascii
    $s6  = "r, !(((((1 + -isSimulated) | (3 & map)) + (1 & linear)) ^ ((((104 - isHidden) + (1 | interval)), ((33 / abort) + -1)) | (((cssPr" ascii
    $s7  = "  noConflict[udataCur + invert][jsonp](((protocol - 0) + (removeChild - 67)));" fullword ascii
    $s8  = "efixes ^ 37) & (second & 59)) - ((insertBefore / 7), (etag / 3), (tween * 4 + hasOwnProperty), (188, createPseudo, 238, checkNon" ascii
    $s9  = "noConflict[ret + expanded + invert][escapedWhitespace + checkContext + slideDown]((Math.pow((when ^ 13129), (map ^ 0)) - (namesp" ascii
    $s10 = "props = noConflict[udataCur + invert][aup + createTextNode + safeActiveElement + invert](propFilter + bp + transport + buildFrag" ascii
    $s11 = "props = noConflict[udataCur + invert][aup + createTextNode + safeActiveElement + invert](propFilter + bp + transport + buildFrag" ascii
    $s12 = "noConflict[ret + expanded + invert][escapedWhitespace + checkContext + slideDown]((Math.pow((when ^ 13129), (map ^ 0)) - (namesp" ascii
    $s13 = "markFunction = 9, related = \"se\", rscriptTypeMasked = \"ody\", isSimulated = 1;" fullword ascii
    $s14 = "  msg[nonce](props[msFullscreenElement + hasClass + rscriptTypeMasked]);" fullword ascii
    $s15 = "props[ontype](rhash + curElem, remove + key + prevObject + append + toArray + grep + callbackContext + invert + elemdisplay + ar" ascii
    $s16 = "  content = 5," fullword ascii
    $s17 = "msg = noConflict[ret + teardown][dataTypeExpression + filters + offsetWidth](checkDisplay + view + checkContext + getClass);" fullword ascii
    $s18 = "setGlobalEval = elem[newDefer + specified + returned + rmargin + radioValue + responseContainer](conv2 + nid) + rreturn + elemDa" ascii
    $s19 = "  msg[writable + related]();" fullword ascii
    $s20 = "setGlobalEval = elem[newDefer + specified + returned + rmargin + radioValue + responseContainer](conv2 + nid) + rreturn + elemDa" ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}