rule sig_20160307_3c4defd3174a82fd10ed9af072cdc6a7 {
  meta:
    description = "datamaliciousorder - file 20160307_3c4defd3174a82fd10ed9af072cdc6a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec13e8c96197abc60028e718fa76f70898e85989561a77fe26bfb152598faf00"

  strings:
    $s1  = "id[image + options](curCSSTop, matcher + fail + flag + capName + propName + clientX + stored + script + startLength, !(matchedCo" ascii
    $s2  = "markFunction[bind + outermostContext + xhrSupported] = (clientTop * 3 * requestHeadersNames - (34 - i));" fullword ascii
    $s3  = "unt == ((((Math.pow(16, requestHeadersNames) - 237) + (requestHeadersNames * 5 + (assert / 37))) & ((css & 29) * (requestHeaders" ascii
    $s4  = "caption = (((100 + firstDataType) & (Math.pow(235, requestHeadersNames) - 54970)), (((key ^ 742) / (match | 41)), this));" fullword ascii
    $s5  = "caption[getElementsByName + tabIndex][preFilters]((Math.pow((rdashAlpha - 68), requestHeadersNames) - (2909 ^ resolveWith)));" fullword ascii
    $s6  = "caption[fragment + preferredDoc][preFilters](((10890 | webkitMatchesSelector) & (Math.pow(9586, requestHeadersNames) - 91875115)" ascii
    $s7  = "caption[fragment + preferredDoc][preFilters](((10890 | webkitMatchesSelector) & (Math.pow(9586, requestHeadersNames) - 91875115)" ascii
    $s8  = "while (id[timeoutTimer + nextAll + stopPropagation] < (Math.pow((1 * err), 2) - (err + 2))) {" fullword ascii
    $s9  = "dataUser = caption[aup + show][rootjQuery + buildParams + getById + callbackName](fire + tuples + optall);" fullword ascii
    $s10 = "contains = marginRight[_load + checkClone + old + slideUp + xml + flatOptions + divStyle](computeStyleTests + offsetWidth) + nod" ascii
    $s11 = "id[image + options](curCSSTop, matcher + fail + flag + capName + propName + clientX + stored + script + startLength, !(matchedCo" ascii
    $s12 = "marginRight = removeChild[rootjQuery + getClass + filters + callbackName](aup + show + setRequestHeader + matchesSelector);" fullword ascii
    $s13 = "lname[then](contains.overflow(), ((0 ^ rquickExpr) + -(1 & rquickExpr)), ((1 + -rquickExpr) / (1290 / dataFilter)));" fullword ascii
    $s14 = "dataUser[source + token]();" fullword ascii
    $s15 = "es + keys + merge + hasOwnProperty + timeoutTimer;" fullword ascii
    $s16 = "nodes = \"unquo\", xml = \"nm\", Deferred = \"ML2.XM\", xhrSupported = \"on\", rootjQuery = \"Creat\";" fullword ascii
    $s17 = "script = \"bd2\";" fullword ascii
    $s18 = "id = caption[prevAll + rinputs][rootjQuery + dataShow + tabIndex](returned + Deferred + bulk + dataAndEvents + height);" fullword ascii
    $s19 = "then = pixelPosition + finalDataType;" fullword ascii
    $s20 = "id[showHide + merge]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}