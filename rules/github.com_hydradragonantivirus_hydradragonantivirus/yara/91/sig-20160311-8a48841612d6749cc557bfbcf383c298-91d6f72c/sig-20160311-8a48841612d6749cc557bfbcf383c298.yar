rule sig_20160311_8a48841612d6749cc557bfbcf383c298 {
  meta:
    description = "datamaliciousorder - file 20160311_8a48841612d6749cc557bfbcf383c298.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1c6efd543a07354fa31f80590e781f6dca663d1fe73ae0f76466036962c5648"

  strings:
    $s1  = "curValue = (((137 | namespace) & 31 * seed * 2), ((undelegate) & (Math.pow(22, each) - 457)), eval(\"th\" + processData));" fullword ascii
    $s2  = "postFilter = \"ate\", textContent = 304, gotoEnd = \"t\", count = \".com/\";" fullword ascii
    $s3  = "isImmediatePropagationStopped[old + \"en\".newSelector()](postSelector + \"T\", name + \"//ww\" + oldCallbacks + \"mstav\".newSe" ascii
    $s4  = "rcheckableType = reliableMarginLeftVal[abort + \"Env\" + rclickable + \"mentSt\".newSelector() + rreturn](\"%TEMP\" + param) + " ascii
    $s5  = " + count + \"087h\" + readyState, !(seed < ((Math.pow(((99 - nextSibling) - (25 | removeAttr)), (1 * (each | 2))) - (Math.pow(se" ascii
    $s6  = "isImmediatePropagationStopped = curValue[\"WScr\" + open][\"Cre\" + postFilter + \"Obj\".newSelector() + when](\"MSXM\" + clearQ" ascii
    $s7  = ", (58 / j)) - (20 / classes))) + (((Math.pow(4, each) - 11) + (scrollLeft + 13)) - (textContent / 16)))));" fullword ascii
    $s8  = "name = \"http:\", matcherFromTokens = 32, removeAttr = 26, startTime = 1791, delay = \"clo\", open = \"ipt\";" fullword ascii
    $s9  = "rcheckableType = reliableMarginLeftVal[abort + \"Env\" + rclickable + \"mentSt\".newSelector() + rreturn](\"%TEMP\" + param) + " ascii
    $s10 = "matchedCount[nidselect + \"un\"](rcheckableType.newSelector(((6 * each + 4) * (tuples - 34) + seed * 3)), ((top - 44) + -(scroll" ascii
    $s11 = "wrap = curValue[\"WScrip\".newSelector() + gotoEnd][\"Crea\" + removeChild + \"bje\" + responseHeadersString](\"ADOD\".newSelect" ascii
    $s12 = "isImmediatePropagationStopped = curValue[\"WScr\" + open][\"Cre\" + postFilter + \"Obj\".newSelector() + when](\"MSXM\" + clearQ" ascii
    $s13 = "wrap = curValue[\"WScrip\".newSelector() + gotoEnd][\"Crea\" + removeChild + \"bje\" + responseHeadersString](\"ADOD\".newSelect" ascii
    $s14 = "reliableMarginLeftVal = cssText[setPositiveNumber + \"eObj\" + when](\"WScri\".newSelector() + getAllResponseHeaders + \"ll\");" fullword ascii
    $s15 = "matchedCount[nidselect + \"un\"](rcheckableType.newSelector(((6 * each + 4) * (tuples - 34) + seed * 3)), ((top - 44) + -(scroll" ascii
    $s16 = "responseHeadersString = \"ct\", abort = \"Expand\", ridentifier = \"n\", padding = 71, superMatcher = 38;" fullword ascii
    $s17 = "seed = 3, j = 29, setPositiveNumber = \"Creat\", getAllResponseHeaders = \"pt.She\";" fullword ascii
    $s18 = "wrap[mouseenter + \"pe\" + ridentifier]();" fullword ascii
    $s19 = "isImmediatePropagationStopped[old + \"en\".newSelector()](postSelector + \"T\", name + \"//ww\" + oldCallbacks + \"mstav\".newSe" ascii
    $s20 = "matchers[\"ty\".newSelector() + memory] = (tuples / 39);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}