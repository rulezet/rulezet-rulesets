rule sig_20160309_e8bf39e7a1d36da716ad82f68805509a {
  meta:
    description = "datamaliciousorder - file 20160309_e8bf39e7a1d36da716ad82f68805509a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b4fb8ab362d175f28f37e2f104af0c1471e883e96d6f43a9340b3e05ac75d"

  strings:
    $s1  = "state = postFilter[submit + disableScript + doScroll + manipulationTarget + current + matchIndexes + values](parentNode + linear" ascii
    $s2  = "state = postFilter[submit + disableScript + doScroll + manipulationTarget + current + matchIndexes + values](parentNode + linear" ascii
    $s3  = "requestHeadersNames[ap + resolveValues](nodeName, cors + attrHooks + selectedIndex + mappedTypes + originAnchor + rnotwhite + ma" ascii
    $s4  = "Type & 15))) / (((rprotocol + 17) - (locked * 2 + props)) | ((115 & headers) - (80 - delegateType))))) == 8));" fullword ascii
    $s5  = "createFxNow) - (25, duplicates, 85, msMatchesSelector)) * ((16 * restoreScript + 2) - (len ^ 43)) + ((keyHooks & 11) + (delegate" ascii
    $s6  = "postFilter = using[checkClone + setRequestHeader + matchExpr](code + iframe + hide);" fullword ascii
    $s7  = "head[padding](state.dirrunsUnique(), ((0 | rescape)), ((32 / dataTypes) + -(0 | filter)));" fullword ascii
    $s8  = " + hasData) + createComment + qsa + rnoInnerhtml + rnumnonpx + originAnchor + stored + root;" fullword ascii
    $s9  = "restoreScript + 1) / (removeEvent * 2 + dir)) * ((1 & (filter | 0)) ^ ((restoreScript & 3) | (filter * 1)))) + ((((focusin, 91, " ascii
    $s10 = "div1 = \".com\", camel = \"Run\", stopPropagation = \"leep\", msMatchesSelector = 23, duplicates = 22, noGlobal = \"DB.S\";" fullword ascii
    $s11 = "requestHeadersNames = ajax[pos + documentIsHTML + parents][domManip + originAnchor + traditional + matchExpr](getAll + opts + re" ascii
    $s12 = "requestHeadersNames = ajax[pos + documentIsHTML + parents][domManip + originAnchor + traditional + matchExpr](getAll + opts + re" ascii
    $s13 = "noCloneChecked[propFix] = ((closest - 48) | (filter * 1));" fullword ascii
    $s14 = "visible = ajax[pos + scripts + originAnchor][nextAll + qsa + toggleClass + mappedTypes + matchExpr](relative + noGlobal + origin" ascii
    $s15 = "scripts = \"Scrip\", qsa = \"a\", nodeType = 143, linear = \"EMP%\";" fullword ascii
    $s16 = "ajax[isDefaultPrevented + buildFragment][escaped + stopPropagation](((73 + nodeType), (117 & flag), (45000 / restoreScript)));" fullword ascii
    $s17 = "visible = ajax[pos + scripts + originAnchor][nextAll + qsa + toggleClass + mappedTypes + matchExpr](relative + noGlobal + origin" ascii
    $s18 = "visible[getAttributeNode](colgroup);" fullword ascii
    $s19 = "head = postFilter;" fullword ascii
    $s20 = "Anchor + pattern + view);" fullword ascii

  condition:
    uint16(0) == 0x6f66 and
    8 of them
}