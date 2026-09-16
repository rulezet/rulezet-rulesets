rule sig_20160309_2ed34f0444274c43c103ce0f73202274 {
  meta:
    description = "datamaliciousorder - file 20160309_2ed34f0444274c43c103ce0f73202274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d537e446a9830ea2c63a1ee299c219d60899c248f2257c810b74d95c4235349"

  strings:
    $s1  = "option[fromCharCode](returnFalse + domManip, timeoutTimer + fadeToggle + jqXHR + processData + compareDocumentPosition + cacheUR" ascii
    $s2  = "option[fromCharCode](returnFalse + domManip, timeoutTimer + fadeToggle + jqXHR + processData + compareDocumentPosition + cacheUR" ascii
    $s3  = "preMap = rsubmittable[contentDocument + jsonp + animation][matcherFromTokens + progressValues + superMatcher + animation](delay " ascii
    $s4  = "preMap = rsubmittable[contentDocument + jsonp + animation][matcherFromTokens + progressValues + superMatcher + animation](delay " ascii
    $s5  = "rsubmittable[checkNonElements + jqXHR + animation][offset](((dispatch / 44) + (Math.pow(bySet, 2) - adjusted)));" fullword ascii
    $s6  = "option = rsubmittable[contentDocument + status][add + send + _queueHooks + animation](getElementsByClassName + scale + type + le" ascii
    $s7  = "option = rsubmittable[contentDocument + status][add + send + _queueHooks + animation](getElementsByClassName + scale + type + le" ascii
    $s8  = "defer = define[num + arg + clearQueue + animation](div + td + dataTypeOrTransport + compile);" fullword ascii
    $s9  = "each = high + getAllResponseHeaders;" fullword ascii
    $s10 = "boxSizingReliable[undelegate + beforeSend] = ((contents, 1) + (newCache - 40));" fullword ascii
    $s11 = "rwhitespace = defer[rcombinators + attrHooks + cssHooks + grep + swing](globalEventContext + preferredDoc) + tmp + originalPrope" ascii
    $s12 = "rwhitespace = defer[rcombinators + attrHooks + cssHooks + grep + swing](globalEventContext + preferredDoc) + tmp + originalPrope" ascii
    $s13 = "checked = \"m\", cacheURL = \".com.\", attrHooks = \"pandEn\", onabort = \"te\";" fullword ascii
    $s14 = "checkNonElements = \"WScri\", contentDocument = \"WScr\", div = \"WS\", progressValues = \"e\", returned = 34, add = \"Create\";" ascii
    $s15 = "option[getAttribute]();" fullword ascii
    $s16 = "contents = 71;" fullword ascii
    $s17 = "button = \"/log\";" fullword ascii
    $s18 = "backgroundClip = option[fireGlobals + risSimple + radioValue];" fullword ascii
    $s19 = "prefix[each](rwhitespace.replaceChild(), ((28 & outermost) - (4 * cached)), ((1 & origFn) | (1 * origFn)));" fullword ascii
    $s20 = "L + innerText + border + options + els + checked + button + valHooks + el + flatOptions, !(((((11 + selected), (21 * parents), 2" ascii

  condition:
    uint16(0) == 0x7773 and
    8 of them
}