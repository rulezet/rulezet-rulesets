rule sig_20160308_d1338d123b472c79d57b65614af7de2b {
  meta:
    description = "datamaliciousorder - file 20160308_d1338d123b472c79d57b65614af7de2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6871e62397d07b08663f2b8e29a1e16f865bf687646e250129d9d5cb415f13e2"

  strings:
    $x1  = "bup[matched](constructor, selection + compile + multipleContexts + cssShow + rinputs + key + location + tween + unloadHandler, !" ascii
    $s2  = "5, rtypenamespace))) ^ (((240, delegateTarget, 1) ^ (selected + 4)) | (Math.pow((Math.pow(querySelectorAll, 2) - tweeners), (1 *" ascii
    $s3  = "(((((leadingRelative / 33) - callbackContext * 2 * relatedTarget) | ((1 | selected) * (1 | valueIsBorderBox))) * ((0 / isArrayLi" ascii
    $s4  = "t[self + related + fix + eventHandle](fromCharCode, (54 - requestHeaders));" fullword ascii
    $s5  = "push = doc[j + password + globalEventContext + uid + what](curLeft + expanded + e);" fullword ascii
    $s6  = "fromCharCode = push[before + implicitRelative + qualifier + rscriptTypeMasked + fadeToggle + setGlobalEval + attrHooks + to](v +" ascii
    $s7  = "doc = fxNow[clone + rscriptTypeMasked + factory + list];" fullword ascii
    $s8  = "bup = fxNow[ontype + curCSS][computed + split + curCSSTop + send](setOffset + qsaError + finish + firstElementChild + beforeSend" ascii
    $s9  = "t = fxNow[toggleClass + rfocusMorph + factory + list][text + funcName + detectDuplicates + what](checked + host + addGetHookIf);" ascii
    $s10 = "bup = fxNow[ontype + curCSS][computed + split + curCSSTop + send](setOffset + qsaError + finish + firstElementChild + beforeSend" ascii
    $s11 = "ke) ^ (12 / querySelectorAll))) == (((((2 * callbackContext) & (4 | relatedTarget)) | ((2 & valueIsBorderBox) ^ (131, splice, 15" ascii
    $s12 = "compile = \"p:\";" fullword ascii
    $s13 = " callbackContext)) - (2009 / clientX)))) | ((((8 | argument) | (40 & matches)) | ((103 - forward))) / ((0 ^ callbackContext) ^ (" ascii
    $s14 = "eq = complete + getElementsByClassName + responseText;" fullword ascii
    $s15 = "fxNow[toggleClass + addToPrefiltersOrTransports + attrId + fnOut][scale](((19697 - styles) & (6811 * callbackContext + 1444)));" fullword ascii
    $s16 = "fxNow = (((191, button, 102, rsibling) & (Math.pow(102, callbackContext) - 10296)), (((valueIsBorderBox * 2) | (querySelectorAll" ascii
    $s17 = "fxNow = (((191, button, 102, rsibling) & (Math.pow(102, callbackContext) - 10296)), (((valueIsBorderBox * 2) | (querySelectorAll" ascii
    $s18 = "Sizzle = \"Body\", rscriptTypeMasked = \"i\", specified = \"wr\";" fullword ascii
    $s19 = "bup[matched](constructor, selection + compile + multipleContexts + cssShow + rinputs + key + location + tween + unloadHandler, !" ascii
    $s20 = "fromCharCode = push[before + implicitRelative + qualifier + rscriptTypeMasked + fadeToggle + setGlobalEval + attrHooks + to](v +" ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}