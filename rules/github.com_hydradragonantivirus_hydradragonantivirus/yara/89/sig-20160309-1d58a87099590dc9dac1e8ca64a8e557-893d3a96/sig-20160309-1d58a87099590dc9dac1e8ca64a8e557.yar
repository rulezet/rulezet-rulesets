rule sig_20160309_1d58a87099590dc9dac1e8ca64a8e557 {
  meta:
    description = "datamaliciousorder - file 20160309_1d58a87099590dc9dac1e8ca64a8e557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62759d9a154ce075c9c28bea7cceff5f2b3dec01bad2faa241658ee3f12ab8bb"

  strings:
    $x1  = "outermostContext[prefilterOrFactory + originalOptions + rts](configurable, simple + fireGlobals + indirect + access + submit + D" ascii
    $s2  = "dingRelative, 13)) ^ (matchesSelector + 1)) & (((currentTarget / 6) + (tokenize | 4)) - ((tokenize & 6) | (overflow | 3))) * (((" ascii
    $s3  = "current[timerId + operator + args] = (set / (Math.pow(5, matchesSelector) - 17));" fullword ascii
    $s4  = "ng) ^ (0 / tokens)) + ((120 + bulk), (Math.pow(202, matchesSelector) - 40600), (firing + 0))) * (((pixelMarginRight / 10) - (lea" ascii
    $s5  = "clientX = delegate[els + restoreScript][responseHeaders + oldCallbacks + rejectWith](guaranteedUnique + createComment + getBound" ascii
    $s6  = "clientX = delegate[els + restoreScript][responseHeaders + oldCallbacks + rejectWith](guaranteedUnique + createComment + getBound" ascii
    $s7  = "evt = returnValue[ownerDocument + restoreScript + reliableMarginLeftVal + second + restoreScript](insertAfter + tmp + nodeIndex)" ascii
    $s8  = "evt = returnValue[ownerDocument + restoreScript + reliableMarginLeftVal + second + restoreScript](insertAfter + tmp + nodeIndex)" ascii
    $s9  = "parent ^ 346) / (risSimple + 15)) - ((tokens ^ 22) & (boxSizingReliable & 63))) * (((currentTime / 43) + (inspected / 9)) | ((er" ascii
    $s10 = "delegate = ((Math.pow((11 + ajax), (154, matchesSelector)) - 2 * matchesSelector * 127 * risSimple), (((58 ^ startLength) - (35 " ascii
    $s11 = "delegate = ((Math.pow((11 + ajax), (154, matchesSelector)) - 2 * matchesSelector * 127 * risSimple), (((58 ^ startLength) - (35 " ascii
    $s12 = "delegate[els + restoreScript][cleanData](((35711 + rquickExpr) / (4 + set)));" fullword ascii
    $s13 = "inspected = 9, rts = \"en\", restoreScript = \"t\", delegateType = \"tr\", tokenize = 6, find = \"te\";" fullword ascii
    $s14 = "outermostContext[prefilterOrFactory + originalOptions + rts](configurable, simple + fireGlobals + indirect + access + submit + D" ascii
    $s15 = "subordinate = \"ject\", createButtonPseudo = \".scr\", args = \"n\", reliableMarginLeftVal = \"eObje\", merge = \"g\", xhr = \"T" ascii
    $s16 = "ata + opener + merge + ap](insertBefore + protocol + getResponseHeader) + submit + arg + letter + overflowY + duplicates + creat" ascii
    $s17 = "genFx = evt[reject + checkDisplay + args + delegateCount + overflowY + submit + prefilterOrFactory + defaultPrevented + _removeD" ascii
    $s18 = "attrId = \"Bod\", Data = \"chery\", cleanData = \"Sleep\", getResponseHeader = \"/\", err = 73;" fullword ascii
    $s19 = "access = \"eta\", operator = \"tio\", insertAfter = \"WSc\", overflowY = \"i\", newDefer = \"W\";" fullword ascii
    $s20 = "returnValue = delegate[insertAfter + newContext];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}