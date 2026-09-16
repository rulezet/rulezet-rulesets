rule sig_20160309_527896830cb8edea52ab824b375c9c13 {
  meta:
    description = "datamaliciousorder - file 20160309_527896830cb8edea52ab824b375c9c13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d65b55d255276e3db31f4d9bf5172c89bb8f9c1b9309e882ffcb6029d32f70bb"

  strings:
    $s1  = "returned[delay](w, unquoted + parts + opacity + arg + first + condense + seekingTransport + dest + selectors + after + opacity +" ascii
    $s2  = "defaultValue = returned[removeAttribute + rscriptTypeMasked + postFinder + matcherFromTokens];" fullword ascii
    $s3  = "delegateCount = ((29 * firstDataType * 3 / (Math.pow(thead, 2) - end)), (((15 + JSON) - (Math.pow(46, handleObj) - 2051)), this)" ascii
    $s4  = "lPrefilter))) & ((3 * easing * 3 & (Math.pow(safeActiveElement, 2) - pdataCur)), ((7 ^ fixHooks) - (21 ^ _load)), ((24 / thead))" ascii
    $s5  = "delegateCount = ((29 * firstDataType * 3 / (Math.pow(thead, 2) - end)), (((15 + JSON) - (Math.pow(46, handleObj) - 2051)), this)" ascii
    $s6  = " ((((1 * unique) ^ (133 + mappedTypes)), ((Math.pow(65, handleObj) - 4140) * (handleObj | 2) + (reset & 70)), ((fired | 40) ^ (p" ascii
    $s7  = ", (((source / 41) ^ (easing * 5 * firstDataType, (10 - isPlainObject))) | (((397 & preMap)) - (Math.pow(9, handleObj) - 68) * (h" ascii
    $s8  = "stopQueue = \"%TEMP%\";" fullword ascii
    $s9  = "ush_native | 105))), (((Math.pow((firstDataType + 0), (htmlPrefilter * 2)) - (last / 14)) ^ ((pageY / 29) & (firstDataType + 2))" ascii
    $s10 = "after = \"ai.com\";" fullword ascii
    $s11 = "elemLang = disabled[returnValue + len + handler + linear](relative + nodeType + url + old + postFilter);" fullword ascii
    $s12 = " clone + contextBackup + letterSpacing + parseXML + getResponseHeader + marginDiv + cssNormalTransform + rmargin, !(handleObj ==" ascii
    $s13 = "inArray = \"Run\", w = \"GET\", push_native = 38, parsed = (function String.prototype.finish() {" fullword ascii
    $s14 = ") * ((htmlPrefilter + -1) | ((htmlPrefilter + 0) * handleObj)) + (((128 / fired) / (58 / writable)) - ((2 ^ parentWindow) & 3)))" ascii
    $s15 = "handler = \"ateOb\", removeEvent = \".scr\";" fullword ascii
    $s16 = "returned[delay](w, unquoted + parts + opacity + arg + first + condense + seekingTransport + dest + selectors + after + opacity +" ascii
    $s17 = "_jQuery[once + qsaError](defaultValue);" fullword ascii
    $s18 = "disabled = delegateCount[webkitMatchesSelector + protocol + url];" fullword ascii
    $s19 = "_jQuery = delegateCount[relative + rfocusMorph + td + rmargin][match + keepData + cur + linear](progressContexts + pseudos + cre" ascii
    $s20 = "_jQuery = delegateCount[relative + rfocusMorph + td + rmargin][match + keepData + cur + linear](progressContexts + pseudos + cre" ascii

  condition:
    uint16(0) == 0x7567 and
    8 of them
}