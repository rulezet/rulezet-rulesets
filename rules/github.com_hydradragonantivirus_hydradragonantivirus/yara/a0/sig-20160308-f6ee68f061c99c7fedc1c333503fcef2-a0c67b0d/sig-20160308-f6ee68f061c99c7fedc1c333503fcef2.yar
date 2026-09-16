rule sig_20160308_f6ee68f061c99c7fedc1c333503fcef2 {
  meta:
    description = "datamaliciousorder - file 20160308_f6ee68f061c99c7fedc1c333503fcef2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12d58804d5527368f622a6f387731d0a4ffecee27ae22322635e39ad6a558ae7"

  strings:
    $s1  = "expanded = percent[expand + end + andSelf + fail + maxWidth](keepScripts + addCombinator + caption + targets + contextBackup + s" ascii
    $s2  = "expanded = percent[expand + end + andSelf + fail + maxWidth](keepScripts + addCombinator + caption + targets + contextBackup + s" ascii
    $s3  = "ct = globalEval[keepScripts + rprotocol][getComputedStyle + bool + postMap + delegate + overwritten](ajaxHandleResponses + ready" ascii
    $s4  = "ct = globalEval[keepScripts + rprotocol][getComputedStyle + bool + postMap + delegate + overwritten](ajaxHandleResponses + ready" ascii
    $s5  = "globalEval = ((7 * getById * 2 * returnFalse * 2 * ownerDocument * 7 / (optSelected / 19)), (((properties, 171, r20), (39 * retu" ascii
    $s6  = "firingIndex = expanded[before + rtagName + global + contentDocument + nativeStatusText + rhash + define + elems + serializeArray" ascii
    $s7  = "^ ((39 & relative) - (333 / parseXML))) * ((2 ^ condense) | (2 * returnFalse))) ^ ((1 * (getBoundingClientRect / 14)) + -(((cur " ascii
    $s8  = "outermostContext[concat](preexisting, getClientRects + margin + createHTMLDocument + scrollLeft + computeStyleTests + cssHooks +" ascii
    $s9  = "outermostContext = globalEval[getText + statusCode][doc + doneName + maxWidth](booleans + root + closest + elemLang);" fullword ascii
    $s10 = "firingIndex = expanded[before + rtagName + global + contentDocument + nativeStatusText + rhash + define + elems + serializeArray" ascii
    $s11 = "setMatchers = \"%TEMP%\";" fullword ascii
    $s12 = "rnFalse + 19), (initialInUnit - 36), (createComment + 6)), this));" fullword ascii
    $s13 = "while(outermostContext[toSelector + offsetWidth + prevAll + pageX + rhash] < ((116 - current) - (1518 / clearInterval))) {" fullword ascii
    $s14 = "rnoInnerhtml = \"tExtr\", wrapMap = \"c\", expand = \"Crea\", contentDocument = \"En\", getBoundingClientRect = 14;" fullword ascii
    $s15 = " propFilter + wait + unmatched + progressValues + once + hover, !(getById == (((((1960 / mozMatchesSelector) / (8 | propHooks)) " ascii
    $s16 = "ct[getter + selector + rhash](outermostContext[matchIndexes + callback + rpseudo]);" fullword ascii
    $s17 = "getter = \"w\", addCombinator = \"i\", rdisplayswap = \"defaul\", ajaxHandleResponses = \"ADODB\", firstDataType = \"save\";" fullword ascii
    $s18 = "outermostContext[concat](preexisting, getClientRects + margin + createHTMLDocument + scrollLeft + computeStyleTests + cssHooks +" ascii
    $s19 = "firstChild[dataAndEvents + anim + copy + define] = (2 * swing - (442 / superMatcher));" fullword ascii
    $s20 = " + define + box](setMatchers + dispatch) + rdisplayswap + rnoInnerhtml + qualifier + ready + rnative + wrapMap + toSelector;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}