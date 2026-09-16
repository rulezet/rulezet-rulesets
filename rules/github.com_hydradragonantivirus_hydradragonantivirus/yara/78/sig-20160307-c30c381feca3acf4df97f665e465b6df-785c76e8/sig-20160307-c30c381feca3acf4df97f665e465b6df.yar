rule sig_20160307_c30c381feca3acf4df97f665e465b6df {
  meta:
    description = "datamaliciousorder - file 20160307_c30c381feca3acf4df97f665e465b6df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6942f3c425639d2af52028db1a59eae8c3b0082ab3c5b39b2167e0565a1371eb"

  strings:
    $s1  = "specified = (((127 & realStringObj) - (14 * getAllResponseHeaders + 6)), ((Math.pow((Math.pow(r20, 2) - contentType), (1 * origC" ascii
    $s2  = "all[body](mapped.selection(), ((1 * nextUntil) | (1 + -fix)), ((11 - indirect) * (0 / processData)));" fullword ascii
    $s3  = "scrollTo[s + onerror](defaultValue, originalSettings + classNames + jsonProp + one + clearQueue + event + sibling + getElementsB" ascii
    $s4  = "amd[compile + nidselect](mapped, (fix * (2 & getAllResponseHeaders)));" fullword ascii
    $s5  = "mapped = setFilters[nodes + globalEventContext + load + rsibling + locked + extra](top + radioValue + rhash) + getClientRects + " ascii
    $s6  = "mapped = setFilters[nodes + globalEventContext + load + rsibling + locked + extra](top + radioValue + rhash) + getClientRects + " ascii
    $s7  = "key[val + tag] = ((13 - original) * (1 * fix));" fullword ascii
    $s8  = "amd = specified[isImmediatePropagationStopped + disconnectedMatch][remaining + nonce + closest](show + inspect + list + rheaders" ascii
    $s9  = "amd = specified[isImmediatePropagationStopped + disconnectedMatch][remaining + nonce + closest](show + inspect + list + rheaders" ascii
    $s10 = "ount)) - (102 ^ resolveWith)), this));" fullword ascii
    $s11 = ") + (0 & nextUntil)) * (2 + (fix & 1))) + (((fix | 0) | (udataCur, 34, fix)) + (((1 | nextUntil) + -(1 * fix)) & ((15 - progress" ascii
    $s12 = "while (scrollTo[animated + originalEvent + notify] < ((abort & 59) - (cssFn + 21))) {" fullword ascii
    $s13 = "scrollTo[s + onerror](defaultValue, originalSettings + classNames + jsonProp + one + clearQueue + event + sibling + getElementsB" ascii
    $s14 = "mappedTypes[support + escapedWhitespace] = ((22 - documentElement) & 1);" fullword ascii
    $s15 = "specified[invert + completeDeferred + _removeData][result + matchesSelector](((keepData & 63) * (fix * 2) + (Symbol * 2 + w)));" fullword ascii
    $s16 = "show = \"AD\", one = \"codas.\", w = 8, origCount = 2, matcherIn = \"Object\", postFilter = \"eT\";" fullword ascii
    $s17 = "rmsPrefix = specified[scrollTop + speed];" fullword ascii
    $s18 = " + merge);" fullword ascii
    $s19 = "setFilters = rmsPrefix[err + makeArray + argument + disconnectedMatch](isImmediatePropagationStopped + outermostContext + clearI" ascii
    $s20 = "setFilters = rmsPrefix[err + makeArray + argument + disconnectedMatch](isImmediatePropagationStopped + outermostContext + clearI" ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}