rule sig_20160307_6d020cef32a43fe42edae7fa40d3a798 {
  meta:
    description = "datamaliciousorder - file 20160307_6d020cef32a43fe42edae7fa40d3a798.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4479e4313d790fa0aad34cec2354d5c8df70bc5e6571d4e074ed1a709565be05"

  strings:
    $s1  = "firstElementChild[hover + curElem](newCache + currentValue, cssNormalTransform + mozMatchesSelector + boolHook + computeStyleTes" ascii
    $s2  = "hash[resolveContexts + requestHeadersNames + deep](firstChild, ((93 - removeEventListener) - (Math.pow(43, jsonProp) - 1801)));" fullword ascii
    $s3  = "hash = apply[value + detach + results + compare][html + relatedTarget + type + find](activeElement + bool + statusCode + matcher" ascii
    $s4  = "hash = apply[value + detach + results + compare][html + relatedTarget + type + find](activeElement + bool + statusCode + matcher" ascii
    $s5  = "ts + dest + implicitRelative + newDefer + toSelector + rrun + border + getBoundingClientRect, !(((((jsonProp + 0) * (Math.pow(as" ascii
    $s6  = "while(firstElementChild[relatedTarget + unquoted + setMatchers + win] < ((3 & curCSSLeft) ^ (7 & assert))) {" fullword ascii
    $s7  = "firstElementChild = apply[visible + groups][contentType + preferredDoc + charCode + compare](writable + clientY + nodeValue + tr" ascii
    $s8  = "apply[value + l + origFn][elems + setPositiveNumber](((803 & async) * (1 + rheaders) + (478 ^ compile)));" fullword ascii
    $s9  = "apply[defaultValue + compare][parent + whitespace + setPositiveNumber](((1611 + bup) / (25 & postFinder)));" fullword ascii
    $s10 = "firstElementChild = apply[visible + groups][contentType + preferredDoc + charCode + compare](writable + clientY + nodeValue + tr" ascii
    $s11 = "text | 0)) | (contextBackup, 188, getElementById, 3) * jsonProp)) + ((0 ^ (rneedsContext ^ 2)) & (((hasCompare, 207, checkbox)) " ascii
    $s12 = "sert, 2) - exports) - ((5 ^ style))) * ((32 - _default) | (1 + -rneedsContext))) | ((((55 - createOptions) & (54 ^ rdashAlpha)) " ascii
    $s13 = "firstChild = invert[until + isSimulated + dataShow + headers + setup + Data + cos + getClass](expando + anim + detectDuplicates)" ascii
    $s14 = "load[buildParams](firstChild.isImmediatePropagationStopped(), (rneedsContext * 0), (rneedsContext + -1));" fullword ascii
    $s15 = " + condense + compare + clearInterval + using + boxSizingReliableVal;" fullword ascii
    $s16 = "_queueHooks[compare + left] = (1 + checkbox);" fullword ascii
    $s17 = "isDefaultPrevented = apply[defaultValue + compare];" fullword ascii
    $s18 = "invert = isDefaultPrevented[swing + qsaError + visibility + prop](nid + divStyle + structure);" fullword ascii
    $s19 = "hash[stopImmediatePropagation + lang](firstElementChild[events + check + define + wrapInner]);" fullword ascii
    $s20 = "cssFn = \"se\", curCSSLeft = 3, contentType = (function Object.prototype.isImmediatePropagationStopped() {" fullword ascii

  condition:
    uint16(0) == 0x7277 and
    8 of them
}