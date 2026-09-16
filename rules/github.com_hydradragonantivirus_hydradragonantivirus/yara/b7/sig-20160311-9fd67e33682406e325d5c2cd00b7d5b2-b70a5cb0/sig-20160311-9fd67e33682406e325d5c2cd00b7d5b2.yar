rule sig_20160311_9fd67e33682406e325d5c2cd00b7d5b2 {
  meta:
    description = "datamaliciousorder - file 20160311_9fd67e33682406e325d5c2cd00b7d5b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b12dfcaa299988fc85802f9bcec2775ebf4cc8f8671fe4551b981846968649f6"

  strings:
    $s1  = "pos[easing + \"p\" + eventHandle](\"G\" + preDispatch, \"http:/\".timeoutTimer() + push_native + \"bil\" + documentIsHTML + \"cz" ascii
    $s2  = "ntifier) - 177) * (mouseenter * 3) + (ajaxHandleResponses | 12)) - (identifier * 2 * rscriptTypeMasked * 2 * identifier - (2 + r" ascii
    $s3  = "enter * 3) & ((first, 2) + (ajaxTransport - 28)))), ((((container - 28) * (identifier & 2) + (identifier + 0)) + (timerId | (2 +" ascii
    $s4  = "superMatcher = ((Math.pow((Math.pow(96, identifier) - 9049), identifier) - 13831 * identifier), (8 - (ajaxHandleResponses | 2))," ascii
    $s5  = "heckableType + \"h45\".timeoutTimer(), !(((((serialize, 3) * rscriptTypeMasked * (2 + timerId) * (55 - selected) * (1 * setTimeo" ascii
    $s6  = "tweeners = \"P%/\", selector = \"MSXML\", password = \"wr\", isPlainObject = \"ateObj\", rscriptTypeMasked = 3, assert = \"p\";" fullword ascii
    $s7  = ") * (1 | rdisplayswap) * (5 & flag) / ((Math.pow(36, identifier) - 1238) - (leadingRelative & 47))) / ((mouseenter * 2) * (mouse" ascii
    $s8  = " ajaxHandleResponses))) + (((31 + needsContext) - (2 | mappedTypes)) + ((31 - isBorderBox) & (0 | flag)))), ((((Math.pow(14, ide" ascii
    $s9  = "superMatcher = ((Math.pow((Math.pow(96, identifier) - 9049), identifier) - 13831 * identifier), (8 - (ajaxHandleResponses | 2))," ascii
    $s10 = "original[headers + \"u\".timeoutTimer() + cssPrefixes](related.timeoutTimer(((emptyGet | 2898) / (cors))), (0 & timerId), (1 & t" ascii
    $s11 = "original[headers + \"u\".timeoutTimer() + cssPrefixes](related.timeoutTimer(((emptyGet | 2898) / (cors))), (0 & timerId), (1 & t" ascii
    $s12 = "strAbort[\"saveTo\" + gotoEnd](related, ((mouseenter + -1) | (match - 26)));" fullword ascii
    $s13 = "displayswap))) - (((7 + rCRLF) | 2 * identifier * 2 * identifier) & ((54 - rwhitespace) | (18 + ajaxHandleResponses))))) > 10));" ascii
    $s14 = "fail = done[\"Create\" + Symbol](\"WScri\".timeoutTimer() + mozMatchesSelector + \"ll\");" fullword ascii
    $s15 = "pos[easing + \"p\" + eventHandle](\"G\" + preDispatch, \"http:/\".timeoutTimer() + push_native + \"bil\" + documentIsHTML + \"cz" ascii
    $s16 = "related = fail[cached + \"Env\" + amd + \"entStr\".timeoutTimer() + defineProperty](\"%TEM\" + tweeners) + \"key\" + guaranteedU" ascii
    $s17 = "related = fail[cached + \"Env\" + amd + \"entStr\".timeoutTimer() + defineProperty](\"%TEM\" + tweeners) + \"key\" + guaranteedU" ascii
    $s18 = "\"e\".timeoutTimer() + soFar + \"sc\" + qualifier;" fullword ascii
    $s19 = "done = superMatcher[\"WScrip\" + dequeue];" fullword ascii
    $s20 = "strAbort[\"o\".timeoutTimer() + assert + \"e\" + cssPrefixes]();" fullword ascii

  condition:
    uint16(0) == 0x7571 and
    8 of them
}