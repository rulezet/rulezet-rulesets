rule sig_20160308_6f7525a0f0df6064a3fb17cfdab6f731 {
  meta:
    description = "datamaliciousorder - file 20160308_6f7525a0f0df6064a3fb17cfdab6f731.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e7c622e9279d038fe478d6e9d0e06656cfd2d8fe4e6ba0d81c33625070f69bb"

  strings:
    $s1  = "thead + unshift + disableScript + domManip + originalOptions + apply, !(1 < (((((style & 509) / (onerror - 17)) + ((docElem | 16" ascii
    $s2  = "matchers[addToPrefiltersOrTransports](escaped + indirect, disconnectedMatch + updateFunc + requestHeaders + boxSizingReliable + " ascii
    $s3  = "getScript[props](removeEventListener.inArray(), ((0 / stopQueue) ^ (60, _removeData)), ((133, forward, 15), (_removeData / 32)))" ascii
    $s4  = "getScript[props](removeEventListener.inArray(), ((0 / stopQueue) ^ (60, _removeData)), ((133, forward, 15), (_removeData / 32)))" ascii
    $s5  = "script = (((630 / response) + 28), (((Math.pow(pixelPosition, 2) - structure) / (3 ^ tuples)), this));" fullword ascii
    $s6  = "elemLang[addHandle + setup + prevAll + iframe + func] = (7 - (Math.pow(matcherFromTokens, 2) - children));" fullword ascii
    $s7  = "matchers = script[responseText + close][specified + position + slideDown + source + attaches](prototype + progressValues + destE" ascii
    $s8  = "defer = script[attrHooks + compiled + vendorPropName][specified + win + initial + not + isReady + source + attaches](disable + p" ascii
    $s9  = "defer = script[attrHooks + compiled + vendorPropName][specified + win + initial + not + isReady + source + attaches](disable + p" ascii
    $s10 = "while (matchers[postDispatch + high] < ((42, parent, 0), (parentNode ^ 2), (matcherFromTokens & 7))) {" fullword ascii
    $s11 = "iframe = \"o\", docElem = 22, postDispatch = \"ready\", prototype = \"MS\";" fullword ascii
    $s12 = "defer[udataCur + now + prevAll + setOffset + unshift](removeEventListener, ((2 | _removeData) & (27 - noConflict)));" fullword ascii
    $s13 = "script[finalValue + onreadystatechange + win + readyList + vendorPropName][hasScripts]((ofType * 5 * removeData * 2 * removeData" ascii
    $s14 = "script[finalValue + onreadystatechange + byElement][rscriptTypeMasked + rsingleTag + addHandle]((rclass * 2 * hide ^ (14991 - cu" ascii
    $s15 = "matchers = script[responseText + close][specified + position + slideDown + source + attaches](prototype + progressValues + destE" ascii
    $s16 = "script[finalValue + onreadystatechange + win + readyList + vendorPropName][hasScripts]((ofType * 5 * removeData * 2 * removeData" ascii
    $s17 = "parentWindow = script[finalValue + type];" fullword ascii
    $s18 = "script[finalValue + onreadystatechange + byElement][rscriptTypeMasked + rsingleTag + addHandle]((rclass * 2 * hide ^ (14991 - cu" ascii
    $s19 = "matchers[addToPrefiltersOrTransports](escaped + indirect, disconnectedMatch + updateFunc + requestHeaders + boxSizingReliable + " ascii
    $s20 = "2 * removeData * 29 * removeData + (12 | fromCharCode)), ((3 ^ load) - (28 + newContext)))))));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}