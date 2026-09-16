rule sig_20160308_6361875dbae61e506c7d7c41c10f2c71 {
  meta:
    description = "datamaliciousorder - file 20160308_6361875dbae61e506c7d7c41c10f2c71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd65c9b8077b94af3ca01e814d7c8c2e42a5ee6825d0a6ace4458e63b89bb7a3"

  strings:
    $s1  = "marginLeft[results](rquery + resolve, currentValue + which + module + support + tabIndex + cloneCopyEvent + eventHandle + strAbo" ascii
    $s2  = "computeStyleTests = matcherIn[container + rtrim][rfxtypes + pushStack + mouseHooks](get + ajaxHandleResponses + maxWidth + attac" ascii
    $s3  = "computeStyleTests = matcherIn[container + rtrim][rfxtypes + pushStack + mouseHooks](get + ajaxHandleResponses + maxWidth + attac" ascii
    $s4  = "nextUntil[rreturn](genFx.curValue(), (readyState + -(1 + radio)), (30, style, 0));" fullword ascii
    $s5  = "computeStyleTests[inspectPrefiltersOrTransports + related + modified]();" fullword ascii
    $s6  = "marginLeft[results](rquery + resolve, currentValue + which + module + support + tabIndex + cloneCopyEvent + eventHandle + strAbo" ascii
    $s7  = "support = \"k\", rbuggyMatches = \"un\", readyList = 6, tabIndex = \"oko.h\", result = \"je\";" fullword ascii
    $s8  = "rt + jsonp, !(6 == (((((radio | 24) - (ifModified - 67)) * (funcName ^ (6 | radio))) ^ ((0 & radio) & 1)) ^ ((removeAttribute | " ascii
    $s9  = "genFx = fragment[grep + headers + push + submit + once + attrId](bup + newCache + html + testContext) + func + inspectPrefilters" ascii
    $s10 = "indirect[mouseHooks + originAnchor] = ((readyState ^ 0) * readyState);" fullword ascii
    $s11 = "matcherIn[flatOptions + lastChild + offset + rtrim][special + modified + parsed](((Math.pow(nextSibling, 2) - removeClass) * 3 *" ascii
    $s12 = "fragment = rtypenamespace[addToPrefiltersOrTransports + to + MAX_NEGATIVE + qualifier](flatOptions + lastChild + inspectPrefilte" ascii
    $s13 = "fragment = rtypenamespace[addToPrefiltersOrTransports + to + MAX_NEGATIVE + qualifier](flatOptions + lastChild + inspectPrefilte" ascii
    $s14 = "matcherIn[flatOptions + lastChild + offset + rtrim][special + modified + parsed](((Math.pow(nextSibling, 2) - removeClass) * 3 *" ascii
    $s15 = "computeStyleTests[isLocal + originalEvent + pnum + clientY](genFx, (radio | 2));" fullword ascii
    $s16 = "genFx = fragment[grep + headers + push + submit + once + attrId](bup + newCache + html + testContext) + func + inspectPrefilters" ascii
    $s17 = " funcName * 2 + (locked | 404)));" fullword ascii
    $s18 = "while (marginLeft[write + cssHooks + modified] < (removeAttribute) * (58 / setMatchers)) {" fullword ascii
    $s19 = "matcherIn = (((3550 / notify) + (105 + setDocument)), (((11 + originalSettings) + (0 ^ radio)), this));" fullword ascii
    $s20 = "rtypenamespace = matcherIn[source + mouseHooks];" fullword ascii

  condition:
    uint16(0) == 0x6e6f and
    8 of them
}