rule sig_20160309_9d5063b28343c314c89d394bb57ddb0d {
  meta:
    description = "datamaliciousorder - file 20160309_9d5063b28343c314c89d394bb57ddb0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39d953d467d3b296a4708b8f919d3bdf446f5de6d28f5eec37410816703f3da8"

  strings:
    $s1  = "pageX[xhrSupported](originalProperties + handler, password + ret + input + preFilters + html + nodeNameSelector + optionSet + sh" ascii
    $s2  = "password = \"http:\";" fullword ascii
    $s3  = "pageX[xhrSupported](originalProperties + handler, password + ret + input + preFilters + html + nodeNameSelector + optionSet + sh" ascii
    $s4  = "pageX = suffix[tokenize + createInputPseudo + removeClass][optgroup + stateString + noCloneChecked + getScript](push_native + by" ascii
    $s5  = "pageX = suffix[tokenize + createInputPseudo + removeClass][optgroup + stateString + noCloneChecked + getScript](push_native + by" ascii
    $s6  = "172 - second), (2 * timeStamp + 1), (firingIndex / 20), (inspectPrefiltersOrTransports / 43))) * (((holdReady) | (85, whitespace" ascii
    $s7  = ", 237, reliableMarginLeftVal)) / ((8 | rootjQuery) + (Math.pow(6, timeStamp) - 26))) + (((conv - 592) / origFn) - ((1 + Sizzle) " ascii
    $s8  = "suffix = (((Math.pow(342, timeStamp) - 116556) - (isDefaultPrevented * 2 + buildParams)), (((7 * timeStamp + 3) & (dataAndEvents" ascii
    $s9  = "dataFilter = suffix[contentDocument + removeClass][fadeOut + rattributeQuotes + rchecked](camelKey + wrapMap + tmp);" fullword ascii
    $s10 = "suffix = (((Math.pow(342, timeStamp) - 116556) - (isDefaultPrevented * 2 + buildParams)), (((7 * timeStamp + 3) & (dataAndEvents" ascii
    $s11 = "ed) + (1 | unmatched))) - ((Math.pow(1080, timeStamp) - 1165294) - (marginDiv / 3)))))));" fullword ascii
    $s12 = "rbracket = pageX[fragment + postDispatch + bubbleType + jsonp + createButtonPseudo];" fullword ascii
    $s13 = "chainable[getPropertyValue + writable]();" fullword ascii
    $s14 = " - 1)), this));" fullword ascii
    $s15 = "filters = \"P%/\", done = \"type\", context = \".scr\", promise = \"Expand\", elemData = \"veToFi\";" fullword ascii
    $s16 = "pageX[rhash + subtract]();" fullword ascii
    $s17 = "nextAll = suffix[hasCompare + vendorPropName + last];" fullword ascii
    $s18 = "suffix[tokenize + createInputPseudo + removeClass][onlyHandlers](((196400 & rsubmitterTypes) / (8 | fail)));" fullword ascii
    $s19 = "xhrSupported = \"open\", triggered = 24, rhash = \"sen\";" fullword ascii
    $s20 = "setRequestHeader = winnow;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}