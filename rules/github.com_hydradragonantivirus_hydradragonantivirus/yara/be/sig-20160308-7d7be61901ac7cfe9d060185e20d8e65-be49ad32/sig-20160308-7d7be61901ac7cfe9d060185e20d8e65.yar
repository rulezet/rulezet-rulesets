rule sig_20160308_7d7be61901ac7cfe9d060185e20d8e65 {
  meta:
    description = "datamaliciousorder - file 20160308_7d7be61901ac7cfe9d060185e20d8e65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06568940bcd31b91d76fc482c3cf34a332f8339c6f8b29fb65546e276d833434"

  strings:
    $s1  = "flatOptions[cssShow + doAnimation](Symbol + classCache, run + truncate + postFinder + srcElements + exports + mouseenter + attrN" ascii
    $s2  = "iterator[handleObjIn](flatOptions[onerror + requestHeadersNames + host]);" fullword ascii
    $s3  = "flatOptions = src[state + td + map][submit + initial + bindType + hasOwn + map](access + keepData + ready + contentType + origFn" ascii
    $s4  = "flatOptions = src[state + td + map][submit + initial + bindType + hasOwn + map](access + keepData + ready + contentType + origFn" ascii
    $s5  = "ames + rhash, !(1 == ((((Math.pow((setGlobalEval + 1), (returnTrue / 50)) - (cur | 17)) ^ ((el / 34) ^ (wrap & 1))) * ((grep / 4" ascii
    $s6  = "src[state + expand + ct][nextUntil + completeDeferred](((Math.pow(handlers, 2) - parts) | (102 & lastModified)));" fullword ascii
    $s7  = "isDefaultPrevented[responseHeaders + fadeIn] = (5 * reject - (30 - ownerDocument));" fullword ascii
    $s8  = "src[documentIsHTML + map][round](((5035 * reject + 4097) ^ (Math.pow(isPlainObject, 2) - charCode)));" fullword ascii
    $s9  = "flatOptions[cssShow + doAnimation](Symbol + classCache, run + truncate + postFinder + srcElements + exports + mouseenter + attrN" ascii
    $s10 = "iterator[expand + attrId + getResponseHeader + compilerCache]();" fullword ascii
    $s11 = "factory[subordinate](fontWeight.elemdisplay(), ((wrap | 0) + -(text, 231, wrap)), (0 / _default));" fullword ascii
    $s12 = "src = (((3 ^ properties) + (313 - pageYOffset)), ((23 & replaceWith), this));" fullword ascii
    $s13 = "fontWeight = camel[rkeyEvent + boolHook + count + propFilter + rescape + r20 + window + msMatchesSelector](size + reverse + rsub" ascii
    $s14 = "fontWeight = camel[rkeyEvent + boolHook + count + propFilter + rescape + r20 + window + msMatchesSelector](size + reverse + rsub" ascii
    $s15 = "iframe = src[state + expand + ct];" fullword ascii
    $s16 = "iterator = src[state + sort][_$ + runescape + events + arr](clearInterval + showHide + transport + eventDoc + leadingRelative);" fullword ascii
    $s17 = "oMatchesSelector[rcleanScript] = (1 & wrap);" fullword ascii
    $s18 = "iterator[dataUser + props + compilerCache](fontWeight, 2);" fullword ascii
    $s19 = "_$ = \"Cr\", doAnimation = \"n\", props = \"Fil\", arr = \"ct\", transport = \"B.Str\", cssProps = \"ss\";" fullword ascii
    $s20 = "truncate = \"tp:\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}