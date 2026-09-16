rule sig_20160309_5798cc82d9f9f4fa190b89506055dd14 {
  meta:
    description = "datamaliciousorder - file 20160309_5798cc82d9f9f4fa190b89506055dd14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9833433f4c6f1043a61110e0c453ea703803d38958642d82f2eaaae2610702d5"

  strings:
    $s1  = "beforeunload[split](rfocusMorph + augmentWidthOrHeight, html + noGlobal + selectors + sel + rsubmittable + markFunction + i + fi" ascii
    $s2  = "addCombinator = ((130 - documentIsHTML), (((420 / key) & (3 * scrollTop + 2)), this));" fullword ascii
    $s3  = " Expr + exports + select, !(((((combinator - 27) * (converters / 33) * (returnValue | 97) * (tabIndex, 82, apply) / ((102, build" ascii
    $s4  = "beforeunload = addCombinator[tweens + select][using + hasDuplicate + start + file](script + getText + getScript + gotoEnd);" fullword ascii
    $s5  = "appendTo = pixelMarginRightVal[firingIndex + fix + map + proxy + select](oMatchesSelector + nodeValue + getById + cssHooks + pre" ascii
    $s6  = "appendTo = pixelMarginRightVal[firingIndex + fix + map + proxy + select](oMatchesSelector + nodeValue + getById + cssHooks + pre" ascii
    $s7  = "stopped[dataTypeExpression + valueIsBorderBox] = ((Math.pow(testContext, 2) - noConflict) - (6 * slideToggle + 3));" fullword ascii
    $s8  = "original[results + rdisplayswap] = (rhtml / (Math.pow(26, apply) - 627));" fullword ascii
    $s9  = " apply) - 3834777) / apply * 2 * apply))) / (((0 ^ simple) / (13 + speed)) | (Math.pow((186 / Symbol), (1 * apply)) - 29)) * ((a" ascii
    $s10 = "ttrHooks / 9) - (webkitMatchesSelector)) * ((40 / simple) + ((19 * apply + 4) - index))) > 2));" fullword ascii
    $s11 = "addCombinator[curCSS + elements + attributes][charCode + fast]((11 * parse * 2 * apply * 5 * hooks * 2 * apply * 5 * hooks / (19" ascii
    $s12 = "addCombinator[curCSS + elements + attributes][charCode + fast]((11 * parse * 2 * apply * 5 * hooks * 2 * apply * 5 * hooks / (19" ascii
    $s13 = "arr = addCombinator[mappedTypes + ownerDocument][pointerenter + parseFromString + ret + compare](origCount + attrNames + jQuery " ascii
    $s14 = "nalDataType + button + rfocusable + matcherFromGroupMatchers + swing + not + type + prefilterOrFactory + currentTime + isReady +" ascii
    $s15 = "arr = addCombinator[mappedTypes + ownerDocument][pointerenter + parseFromString + ret + compare](origCount + attrNames + jQuery " ascii
    $s16 = "script = \"MSX\";" fullword ascii
    $s17 = "buildParams = 82, type = \"m/\", noGlobal = \"tp:\", parseFromString = \"rea\", curValue = \"mpt\";" fullword ascii
    $s18 = "maxIterations = beforeunload[notifyWith + focus + timer + matcherFromGroupMatchers];" fullword ascii
    $s19 = "beforeunload[split](rfocusMorph + augmentWidthOrHeight, html + noGlobal + selectors + sel + rsubmittable + markFunction + i + fi" ascii
    $s20 = "arr[swing + parsed + map + augmentWidthOrHeight + realStringObj + map](ajaxConvert, (webkitMatchesSelector ^ (3 & parse)));" fullword ascii

  condition:
    uint16(0) == 0x4f44 and
    8 of them
}