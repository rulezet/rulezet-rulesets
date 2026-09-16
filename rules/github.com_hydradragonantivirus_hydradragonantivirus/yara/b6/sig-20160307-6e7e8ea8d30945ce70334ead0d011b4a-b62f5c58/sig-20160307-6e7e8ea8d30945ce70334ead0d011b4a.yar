rule sig_20160307_6e7e8ea8d30945ce70334ead0d011b4a {
  meta:
    description = "datamaliciousorder - file 20160307_6e7e8ea8d30945ce70334ead0d011b4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "055d153fe939af9bab41c8d532b1591e283a22d90314948a5067fe8373b0cb48"

  strings:
    $x1  = "nodeIndex[lastChild + hasContent][delegate + getWindow + originalSettings](2 * (siblings / 42) * (Math.pow(set, 2) - unloadHandl" ascii
    $s2  = "isLocal[parents + computeStyleTests](rsubmitterTypes, fns + rwhitespace + nextUntil + getElementsByTagName + noCloneChecked + re" ascii
    $s3  = "dataShow[winnow](trim.offsetWidth(), ((Math.pow(22, rcleanScript) - 460) - (results, 129, rheader)), ((0 ^ bubbleType) / (94 - c" ascii
    $s4  = "nodeIndex[lastChild + hasContent][delegate + getWindow + originalSettings](2 * (siblings / 42) * (Math.pow(set, 2) - unloadHandl" ascii
    $s5  = "rnoInnerhtml[doScroll + initialInUnit + rscriptType + namespace + xml] = ((manipulationTarget ^ 121), (interval / 35), bubbleTyp" ascii
    $s6  = "rnoInnerhtml[doScroll + initialInUnit + rscriptType + namespace + xml] = ((manipulationTarget ^ 121), (interval / 35), bubbleTyp" ascii
    $s7  = "dataShow[winnow](trim.offsetWidth(), ((Math.pow(22, rcleanScript) - 460) - (results, 129, rheader)), ((0 ^ bubbleType) / (94 - c" ascii
    $s8  = "tick[tag + keyHooks + host](trim, ((40 + checkOn) / (22 + disableScript)));" fullword ascii
    $s9  = "5 / apply)) + (0 & (amd & 1))) * ((Math.pow(nextAll, (208, pixelMarginRightVal, 2)) - hide * 2731), ((disableScript ^ 11) | (rcl" ascii
    $s10 = "trim = properties[replaceAll + overflowX + support + fireWith + checkDisplay + updateFunc + elementMatcher + boxSizingReliable +" ascii
    $s11 = "eanScript ^ 8)), ((rneedsContext ^ 121) / (getAttribute * 5 + rcleanScript))) | ((2 | (abort, 77, rnumnonpx, 0)) * (amd ^ 3) * (" ascii
    $s12 = "rcleanScript * 13 / (fadeTo + 0)) * ((minWidth & 47) - (cos)) * ((33 - dataPriv) & (91 / fadeTo)), (((48 / which) & (0 ^ bubbleT" ascii
    $s13 = " buildParams + rinputs](stateString + animated) + context + responseHeadersString + tweens + completeDeferred;" fullword ascii
    $s14 = "while (isLocal[groups + resolveValues + updateFunc] < ((Math.pow(origFn, 2) - simulate) & (152 / oldCallbacks))) {" fullword ascii
    $s15 = "overflowX = \"pand\", finish = \"on\", once = \"teObje\", manipulationTarget = 154;" fullword ascii
    $s16 = "nodeIndex = (((82 + getAll) + 54), (((bubbleType ^ 3) & (fadeTo, 122, rneedsContext, 2)), this));" fullword ascii
    $s17 = "Sizzle = \"os\", fail = \"Shell\", checkDisplay = \"onm\", clearTimeout = \"type\";" fullword ascii
    $s18 = "trim = properties[replaceAll + overflowX + support + fireWith + checkDisplay + updateFunc + elementMatcher + boxSizingReliable +" ascii
    $s19 = "properties = createDocumentFragment[after + submit + once + accepts](values + tr + fired + fail);" fullword ascii
    $s20 = "tick[defaultExtra + updateFunc](isLocal[hasCompare + finish + rinputs + classCache]);" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and 4 of them
}