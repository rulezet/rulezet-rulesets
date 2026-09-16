rule sig_20160308_4f666fe133a46ec0f70d22c37c243263 {
  meta:
    description = "datamaliciousorder - file 20160308_4f666fe133a46ec0f70d22c37c243263.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ae654a68931b7431290393fd4b997ef3e3f42eb22b872eac3e2cff2d791e4f2"

  strings:
    $s1  = "allTypes[oldCallbacks + lock](flag + matchesSelector, getWidthOrHeight + b + actualDisplay + hasOwn + bindType + setMatchers + n" ascii
    $s2  = "isImmediatePropagationStopped[attrId + fadeIn + restoreScript][offset + doScroll]((owner ^ 0) * (onreadystatechange & 7) * (oper" ascii
    $s3  = "class2type = props[origType + startTime + obj + overwritten + e + display + eventDoc + settings + disableScript](iNoClone + para" ascii
    $s4  = "m + head) + merge + high + rkeyEvent + fadeIn + rwhitespace + define;" fullword ascii
    $s5  = "username[boxSizingReliableVal](class2type.scrollLeft(), (container ^ (1 * container)), ((10 * owner + 1) - (matched * 2 + postMa" ascii
    $s6  = "username[boxSizingReliableVal](class2type.scrollLeft(), (container ^ (1 * container)), ((10 * owner + 1) - (matched * 2 + postMa" ascii
    $s7  = "isImmediatePropagationStopped = (((450 - fragment), (9 * raw + 2), (matched * 4 + raw)), (((1 + container) * 3 * postMap * 2), t" ascii
    $s8  = "isImmediatePropagationStopped = (((450 - fragment), (9 * raw + 2), (matched * 4 + raw)), (((1 + container) * 3 * postMap * 2), t" ascii
    $s9  = "mes) + ((79, className, 139, showHide) + (1 + -newCache))), ((Math.pow(23, owner) - 492) * postMap * 2 - ((owner) | (40 ^ doc)))" ascii
    $s10 = "& 1) | (container)) + ((32 - documentElement) / (Math.pow(14, owner) - 171)))))));" fullword ascii
    $s11 = "Right)))) / ((((159 & active) & (153 + duration)) - ((1 * pageX) ^ (1364 / handle))), (((204 ^ trim) + (2285 / onreadystatechang" ascii
    $s12 = "clearCloneStyle[border] = ((19 + raw) - (Math.pow(17, owner) - 265));" fullword ascii
    $s13 = "ator / 36) * onreadystatechange * (2 * owner + 1) * (onreadystatechange | 1) * (uniqueSort - 21) * owner);" fullword ascii
    $s14 = "xhrSupported = isImmediatePropagationStopped[attrId + clientY + notifyWith][size + rsingleTag + rcomma](condense + whitespace + " ascii
    $s15 = "odeName + onerror, !(((((newCache + 2) * (newCache * 2) * ((newCache * 0) ^ (Math.pow(focus, 2) - delegateCount)) + ((1710 / uns" ascii
    $s16 = "isImmediatePropagationStopped[attrId + fadeIn + restoreScript][offset + doScroll]((owner ^ 0) * (onreadystatechange & 7) * (oper" ascii
    $s17 = "xhrSupported = isImmediatePropagationStopped[attrId + clientY + notifyWith][size + rsingleTag + rcomma](condense + whitespace + " ascii
    $s18 = "allTypes = isImmediatePropagationStopped[clearTimeout + notifyWith][refElements + cssFn + disable + fn + notifyWith](script + cu" ascii
    $s19 = "allTypes = isImmediatePropagationStopped[clearTimeout + notifyWith][refElements + cssFn + disable + fn + notifyWith](script + cu" ascii
    $s20 = "rLeft + wrapInner + each + rscriptTypeMasked);" fullword ascii

  condition:
    uint16(0) == 0x6372 and
    8 of them
}