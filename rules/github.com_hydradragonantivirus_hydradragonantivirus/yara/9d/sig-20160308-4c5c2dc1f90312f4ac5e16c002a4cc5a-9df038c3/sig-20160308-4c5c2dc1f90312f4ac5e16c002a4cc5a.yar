rule sig_20160308_4c5c2dc1f90312f4ac5e16c002a4cc5a {
  meta:
    description = "datamaliciousorder - file 20160308_4c5c2dc1f90312f4ac5e16c002a4cc5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43e8c497da2840da9baf9c94563e4aae8936847dbe4ccb42116c2b049f20a1b2"

  strings:
    $s1  = "addGetHookIf[constructor](trim.using(), ((handler - 38) & (qsaError, 119, pointerleave, 0)), ((rmultiDash ^ 61) - (parsed + 0)))" ascii
    $s2  = "addGetHookIf[constructor](trim.using(), ((handler - 38) & (qsaError, 119, pointerleave, 0)), ((rmultiDash ^ 61) - (parsed + 0)))" ascii
    $s3  = "name[concat + write + onlyHandlers](msMatchesSelector + tr, dataPriv + size + getAllResponseHeaders + elem + duration + not + co" ascii
    $s4  = "ap[delegate + offset][dispatch + clazz](((Math.pow(option, 2) - funcName) / 17 * setPositiveNumber));" fullword ascii
    $s5  = "(fixHooks + qualifier) + currentValue + clientY + scripts + replaceWith + after + until;" fullword ascii
    $s6  = "rclass = ap[optall + docElem][attributes + toArray + slideDown + contentDocument + getWidthOrHeight + html](matchAnyContext + rw" ascii
    $s7  = "trim = htmlPrefilter[stopImmediatePropagation + removeData + setGlobalEval + curLeft + insertAfter + includeWidth + elemdisplay]" ascii
    $s8  = "while (name[state + getElementsByName + apply] < (1 * setPositiveNumber) * 2) {" fullword ascii
    $s9  = "0 | (progressContexts)), ((1 & what) + (1 & stateString))) * ((1 | stateString) + ((5 & host)))) * (2 & fixHook)));" fullword ascii
    $s10 = "rclass[rkeyEvent + duration]();" fullword ascii
    $s11 = "ap = (2 * (setPositiveNumber, 17) * (test / 34), (((rrun + 264) / (lock | 32)), this));" fullword ascii
    $s12 = "rmultiDash = 13, until = \"cr\", scripts = \"Find\", pnum = 15000, onload = \"om/o09\";" fullword ascii
    $s13 = "name[concat + write + onlyHandlers](msMatchesSelector + tr, dataPriv + size + getAllResponseHeaders + elem + duration + not + co" ascii
    $s14 = "host = 6, attributes = \"Cr\";" fullword ascii
    $s15 = "mplete + tweener + rmsPrefix + duration + trigger + offsetHeight + onload + rbrace + implicitRelative, !(setPositiveNumber < (((" ascii
    $s16 = "rclass[setter + tr + unit + resolveValues + duration](trim, ((makeArray - 73) - (animation & 31)));" fullword ascii
    $s17 = "trim = htmlPrefilter[stopImmediatePropagation + removeData + setGlobalEval + curLeft + insertAfter + includeWidth + elemdisplay]" ascii
    $s18 = "defer[serialize + write] = ((1 & what) + (1 * stateString));" fullword ascii
    $s19 = "hitespace + duration + charCode);" fullword ascii
    $s20 = "ap[max + html][dispatch + clazz](((3081 / rmultiDash), 2 * superMatcher * 2, (ajax, 231, pnum)));" fullword ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}