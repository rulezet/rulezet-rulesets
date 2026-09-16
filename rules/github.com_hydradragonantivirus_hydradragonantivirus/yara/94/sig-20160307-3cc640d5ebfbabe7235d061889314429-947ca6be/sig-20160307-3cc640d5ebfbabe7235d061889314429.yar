rule sig_20160307_3cc640d5ebfbabe7235d061889314429 {
  meta:
    description = "datamaliciousorder - file 20160307_3cc640d5ebfbabe7235d061889314429.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "950793435a16015402d43acad4f12c07fbebd71d8679e755de5ef44b01934477"

  strings:
    $s1  = "readyList = headers[handle + createComment][uniqueSort + disableScript + pdataCur](overflowX + add + dispatch + crossDomain);" fullword ascii
    $s2  = " + keyHooks + udataCur + simulate + write + ridentifier, !(10 < ((((bind & 183), (groups / 16), types * 5 * submit) - ((14700 / " ascii
    $s3  = "    headers[file + firstChild][operator + parseOnly](((Math.pow(69, submit) - 4676) + types * 3));" fullword ascii
    $s4  = "related[reliableMarginLeft + unqueued](parents, minWidth + has + border + location + finalValue + scale + keyHooks + removeChild" ascii
    $s5  = "sortInput = currentValue[getter + matcherFromTokens + expanded + notifyWith + display](pnum + cssPrefixes + defaultView + eased " ascii
    $s6  = "sortInput = currentValue[getter + matcherFromTokens + expanded + notifyWith + display](pnum + cssPrefixes + defaultView + eased " ascii
    $s7  = "radioValue = \"ll\", ridentifier = \"3r\", getClientRects = \"HTTP\", fromCharCode = 17, register = 3;" fullword ascii
    $s8  = "headers[file + nonce + classes][contexts](((useCache + 333) - (timers - 7837)));" fullword ascii
    $s9  = "headers = (((11232 / gotoEnd) & (79 ^ checkbox)), (((9 - boxSizingReliableVal) + (4 * cacheLength)), this));" fullword ascii
    $s10 = "))) / ((1381 + (progressValues * 3 + pointerenter)) / ((132 - reject) & (2142 / sel)))))));" fullword ascii
    $s11 = "rcleanScript = \"oF\", matcherFromTokens = \"rea\", file = \"WSc\", serialize = \"d\", scale = \".sa\", hasCompare = \"ile\";" fullword ascii
    $s12 = "while(related[optSelected + onabort + success + prevUntil] < ((19 - fromCharCode) * (2 | ret))) {" fullword ascii
    $s13 = "pos) / (1 + expand))) ^ ((((102 + access) * 3 + (keys + 16)) & (register * 11 * pos * 5 * register * 2 * register / (32 | filter" ascii
    $s14 = "    readyList[rscriptTypeMasked](related[hookFn + cacheURL + childNodes + requestHeaders]);" fullword ascii
    $s15 = "related = headers[fadeTo + classes][newUnmatched + expanded + notifyWith + display](boxSizingReliable + matchesSelector + udataO" ascii
    $s16 = "getter = \"C\";" fullword ascii
    $s17 = "operator = \"Sle\";" fullword ascii
    $s18 = "currentValue = headers[fadeTo + classes];" fullword ascii
    $s19 = "related = headers[fadeTo + classes][newUnmatched + expanded + notifyWith + display](boxSizingReliable + matchesSelector + udataO" ascii
    $s20 = "    parentsUntil[combinator + keyHooks + rquery] = (animate * (99, funcName, 58, animate));" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}