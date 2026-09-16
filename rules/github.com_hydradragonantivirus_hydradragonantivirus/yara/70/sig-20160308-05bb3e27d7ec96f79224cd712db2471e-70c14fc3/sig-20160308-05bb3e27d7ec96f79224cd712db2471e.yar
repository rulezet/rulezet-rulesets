rule sig_20160308_05bb3e27d7ec96f79224cd712db2471e {
  meta:
    description = "datamaliciousorder - file 20160308_05bb3e27d7ec96f79224cd712db2471e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "627f2f7fc21620016dc9578f13c6f91709ea0e6f6f6f088738d672c9aebd3317"

  strings:
    $s1  = "hasCompare[self](responseHeaders + parents, startTime + selected + elements + inspectPrefiltersOrTransports + classNames + offse" ascii
    $s2  = "hasCompare = flatOptions[password + a][nextAll + addGetHookIf + requestHeaders + xhr](swing + excess + parentOffset + getter);" fullword ascii
    $s3  = "aup[hasScripts + preFilter + mouseHooks + getWidthOrHeight](contents, (returnFalse, (2 + push_native)));" fullword ascii
    $s4  = "stopImmediatePropagation = uniqueCache[rnoContent + offsetHeight + now](password + t + fail + events + matchedCount);" fullword ascii
    $s5  = "contents = stopImmediatePropagation[swap + step + head + tfoot + memory + delegate + name + container](getElementsByTagName + bu" ascii
    $s6  = "getElementsByTagName = \"%TEMP%\";" fullword ascii
    $s7  = "flatOptions[password + rattributeQuotes + now][animated + filter](((Math.pow(addBack, 2) - eventHandle) - (139 - rclass)));" fullword ascii
    $s8  = "complete[now + percent + classNames] = ((xhrSuccessStatus / 2), (Math.pow(unqueued, 2) - getComputedStyle), (194 & defaultPreven" ascii
    $s9  = "complete[now + percent + classNames] = ((xhrSuccessStatus / 2), (Math.pow(unqueued, 2) - getComputedStyle), (194 & defaultPreven" ascii
    $s10 = "contents = stopImmediatePropagation[swap + step + head + tfoot + memory + delegate + name + container](getElementsByTagName + bu" ascii
    $s11 = "esolveValues / 13) * updateFunc * 3) & ((detach, 96, wrapInner, 1) + (isReady * 10)))), (((Math.pow((trim / 31), sort) - 2143 * " ascii
    $s12 = "flatOptions[checkNonElements + pixelMarginRightVal + replaceAll + now][winnow + getScript](((566 | arg) * (3 * hasClass + 1) + (" ascii
    $s13 = "flatOptions[checkNonElements + pixelMarginRightVal + replaceAll + now][winnow + getScript](((566 | arg) * (3 * hasClass + 1) + (" ascii
    $s14 = "hasCompare[self](responseHeaders + parents, startTime + selected + elements + inspectPrefiltersOrTransports + classNames + offse" ascii
    $s15 = "flatOptions = ((Math.pow(13 * vendorPropName, (165, shift, 67, sort)) - (516 | el)), ((2 * sort * 2 * sort), this));" fullword ascii
    $s16 = " ((Math.pow(83, sort) - 6734) ^ (attrHooks - 57)), (Math.pow((on), (242, disconnectedMatch, 217, sort)) - (63 + setMatchers)))))" ascii
    $s17 = "while(hasCompare[ofType + transport + subtract] < (sort * 3 & (hasClass - 1))) {" fullword ascii
    $s18 = "sort) - ((Math.pow(19, sort) - 328) ^ MAX_NEGATIVE)) - ((95 / hasClass) * 13, ((triggered * 44 + isReady) - (76 | cacheLength))," ascii
    $s19 = "aup = flatOptions[pageXOffset + fixInput][nextAll + next + documentIsHTML + clearInterval + getAttributeNode + now](noConflict +" ascii
    $s20 = "tParent + useCache + detectDuplicates + scriptCharset + href, !((((((234, outermost, 88, compile) * 2 + (hasClass | 20))) ^ (((r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}