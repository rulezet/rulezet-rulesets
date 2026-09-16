rule sig_20160309_17a607747fff3a3a558223b892b59290 {
  meta:
    description = "datamaliciousorder - file 20160309_17a607747fff3a3a558223b892b59290.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "457a703c97c4cd66128d47e0510d18ec6276a28915cf7f1461ec2c331518d266"

  strings:
    $s1  = "elemLang[pixelMarginRightVal](setMatched + setPositiveNumber + col, dirrunsUnique + rquery + hooks + ap + splice + startTime + r" ascii
    $s2  = "isplay & 1)) & ((getScript + 16) - (wrap | 1))))));" fullword ascii
    $s3  = "isDefaultPrevented = ((75 / assert) * (1 + getAttribute) * (3 & statusText) * (15 & operator), (((2 + string) | (1 ^ string)), t" ascii
    $s4  = "isDefaultPrevented = ((75 / assert) * (1 + getAttribute) * (3 & statusText) * (15 & operator), (((2 + string) | (1 ^ string)), t" ascii
    $s5  = "base[tag](isSuccess.val(), ((elemdisplay & 1) & (string)), ((22 - nType) | (1 * string)));" fullword ascii
    $s6  = "var throws = \"%TEMP%\"," fullword ascii
    $s7  = "rscriptType[after + stopQueue]();" fullword ascii
    $s8  = "outermost[fragment + cur + shift](isSuccess, (getAttribute));" fullword ascii
    $s9  = "eturnFalse + uniqueID + parents + inArray + fire + traditional, !(1 == (((string & 1) ^ (string ^ 1)) * (((elemData - 6), (elemd" ascii
    $s10 = "isSuccess = checkDisplay[defaultExtra + defaultView + emptyStyle + truncate + boxSizingReliable + progressValues + removeClass](" ascii
    $s11 = "duration[bup + finalText] = ((win ^ 21) - (onlyHandlers, 15));" fullword ascii
    $s12 = "empty[checkOn + factory] = ((self / 19) * (elemdisplay + -1));" fullword ascii
    $s13 = "throws + getClass) + hasClass + bool + holdReady + fragment + guaranteedUnique + after + splice;" fullword ascii
    $s14 = "outermost[s + keyCode](rts);" fullword ascii
    $s15 = "elemLang[pixelMarginRightVal](setMatched + setPositiveNumber + col, dirrunsUnique + rquery + hooks + ap + splice + startTime + r" ascii
    $s16 = "rscriptType = outermost;" fullword ascii
    $s17 = "checkDisplay = newContext[Callbacks + hasClass + linear + once + token](readyWait + realStringObj + pageYOffset + includeWidth);" ascii
    $s18 = "removeEventListener = \"Run\", setMatched = \"G\", assert = 25, elemData = 48;" fullword ascii
    $s19 = "elemLang = isDefaultPrevented[invert + escapedWhitespace][rpseudo + init + inspect + bup](doAnimation + mozMatchesSelector + get" ascii
    $s20 = "elemLang = isDefaultPrevented[invert + escapedWhitespace][rpseudo + init + inspect + bup](doAnimation + mozMatchesSelector + get" ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}