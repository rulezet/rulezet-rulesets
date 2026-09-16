rule sig_20160308_bf11b1b8d818e3fa9515f91d2f160f2a {
  meta:
    description = "datamaliciousorder - file 20160308_bf11b1b8d818e3fa9515f91d2f160f2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f2aa80078965bc16c4ba5b2b91898856b74dffdf91f1573717a64ee16620cfa"

  strings:
    $s1  = "seed[complete + accepts](pdataOld[realStringObj + elementMatcher + delegateTarget]);" fullword ascii
    $s2  = "pdataOld[cssFn](tweeners, risSimple + siblingCheck + on + markFunction + register + rscriptTypeMasked + uid + removeAttribute + " ascii
    $s3  = "while(pdataOld[_queueHooks + bind + cur + docElem] < (Math.pow((inspected ^ 2), (original & 3)) - (rsingleTag + 1))) {" fullword ascii
    $s4  = "hasFocus = filter[firstChild + currentTarget + progressContexts + returnValue + doneName + tuple + escapedWhitespace](slow + mat" ascii
    $s5  = "Values ^ 428)) | ((msMatchesSelector, 170, needsContext, 90) / (response / 31))) & (Math.pow((parseHTML * 3 * actualDisplay - (3" ascii
    $s6  = "list + tmp + adjustCSS + compare + dest + nextAll + checkOn + funescape, !(((((Math.pow((Sizzle * 2 + rsingleTag), 2) - (resolve" ascii
    $s7  = "hasFocus = filter[firstChild + currentTarget + progressContexts + returnValue + doneName + tuple + escapedWhitespace](slow + mat" ascii
    $s8  = "pdataOld[cssFn](tweeners, risSimple + siblingCheck + on + markFunction + register + rscriptTypeMasked + uid + removeAttribute + " ascii
    $s9  = "seed = addHandle[namespace + getter][attr + PI + simulate + clientTop + inspect](first + to + attrs);" fullword ascii
    $s10 = "ginal ^ 1)) * ((matcherOut ^ 0) ^ (original | 2)) * ((text - 31) | (original + 0)) & (((event / 43) | (actualDisplay & 7)) ^ ((m" ascii
    $s11 = "t[closest](hasFocus.pushStack(), ((55 - pointerenter) - (1 * parseHTML)), ((196 & speed), (155 ^ special), (0 / tag)));" fullword ascii
    $s12 = "caption[slideToggle + uid + completeDeferred + radioValue] = (getElementsByTagName, 92, matcherOut);" fullword ascii
    $s13 = "slow = \"%TEMP\";" fullword ascii
    $s14 = "chIndexes + test) + register + docElem + inspect + ready + next + isEmptyObject;" fullword ascii
    $s15 = " ^ Sizzle)), (1 * (callbackExpect / 41))) - ((relative) & (Math.pow(1641, original) - 2690226)))), (((createOptions / 47) & (ori" ascii
    $s16 = "getter = \"ript\";" fullword ascii
    $s17 = "closest = buildFragment + letter;" fullword ascii
    $s18 = "atcherOut ^ 1) | (specialEasing * 2 + original))))) == 8));" fullword ascii
    $s19 = "clearCloneStyle = addHandle[rcheckableType + related];" fullword ascii
    $s20 = "addHandle[pixelMarginRight + isEmptyObject + related][count + disconnectedMatch](((hold / 44) * specialEasing * 5 + (bulk & 216)" ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}