rule sig_20160307_b3a9480ac63b6fa19d6b6d13fd7f02ca {
  meta:
    description = "datamaliciousorder - file 20160307_b3a9480ac63b6fa19d6b6d13fd7f02ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45e075596c9e6cda4cc0dc93137e7d809d96c5eaaab5cd98cc6c5211eb5a4b17"

  strings:
    $s1  = "nextUntil[swing](currentTarget.script(), ((genFx - 29) | (last, 0)), (oldCallbacks / (760 / then)));" fullword ascii
    $s2  = "curLeft[timers + rnative](currentTarget, ((4 * last + 3) - (tabIndex & 25)));" fullword ascii
    $s3  = "currentTarget = oMatchesSelector[defaultExtra + attrNames + lock + startLength + lock + responses + rmultiDash](success + suppor" ascii
    $s4  = "appendTo[copy + ap + escaped](hold, originalEvent + getById + returned + m + noGlobal + rreturn + complete + newUnmatched + n + " ascii
    $s5  = "success = \"%TEMP\", compiled = (function String.prototype.script() {" fullword ascii
    $s6  = "ajaxConvert[conditionFn + matcherFromTokens][rheader + maxIterations]((Math.pow((5418 ^ dataShow), (1 + duplicates)) - (58172217" ascii
    $s7  = "currentTarget = oMatchesSelector[defaultExtra + attrNames + lock + startLength + lock + responses + rmultiDash](success + suppor" ascii
    $s8  = "ajaxConvert = ((Math.pow((31 + nodeNameSelector), (254, tr, 2)) - isTrigger * 2 * addEventListener), (((Math.pow(38, nativeStatu" ascii
    $s9  = "oMatchesSelector = stored[compiled + whitespace + insertBefore + contents + pdataCur](prefilterOrFactory + camel + getAll + thro" ascii
    $s10 = "oMatchesSelector = stored[compiled + whitespace + insertBefore + contents + pdataCur](prefilterOrFactory + camel + getAll + thro" ascii
    $s11 = "while (appendTo[run + Sizzle + orig] < ((13 + ifModified) - (4 * guaranteedUnique))) {" fullword ascii
    $s12 = "sText) - 1402) - (keyHooks + 8)), this));" fullword ascii
    $s13 = "percent, !(addEventListener < (((Math.pow(((1 * oldCallbacks) ^ (4 * nativeStatusText)), 2) - ((addEventListener + 50) ^ (duplic" ascii
    $s14 = "ates & 0))) + (((duplicates * 2) ^ (Math.pow(addEventListener, 2) - guaranteedUnique)) + ((5832 / jQuery), (21 - addEventListene" ascii
    $s15 = "appendTo = ajaxConvert[conditionFn + matcherFromTokens][image + eventHandle + checkContext + setAttribute](resolveValues + a + a" ascii
    $s16 = "appendTo[copy + ap + escaped](hold, originalEvent + getById + returned + m + noGlobal + rreturn + complete + newUnmatched + n + " ascii
    $s17 = "r)))) - (Math.pow(((1 + oldCallbacks) + (47 - marginRight)) * ((1 * duplicates) * (34 - curOffset)) * ((114 ^ index), (114 + isP" ascii
    $s18 = "lainObject), (2 ^ oldCallbacks)), (((108 / value) & (88, firstDataType, 30, addEventListener)) & ((1 * oldCallbacks) | 2))) - ((" ascii
    $s19 = "appendTo = ajaxConvert[conditionFn + matcherFromTokens][image + eventHandle + checkContext + setAttribute](resolveValues + a + a" ascii
    $s20 = "curLeft = ajaxConvert[jsonpCallback + pdataCur][compiled + speed + pdataCur + orig + params + stop](oldfire + fail + fxNow + wra" ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}