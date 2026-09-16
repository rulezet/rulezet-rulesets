rule sig_20160309_8433b3bfe6fb3b3d890662469ee88cf2 {
  meta:
    description = "datamaliciousorder - file 20160309_8433b3bfe6fb3b3d890662469ee88cf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66d8a7aeae3d3c9d9941cb388d7e73e054ccd7c7660122cc1a491703b11eb49f"

  strings:
    $s1  = "unit[next + matchContext](host, complete + sortInput + deep + triggered + matchExpr + finish + getClass + checkDisplay + undeleg" ascii
    $s2  = "createPseudo = param[valueIsBorderBox + handler + keepData][head + rootjQuery + parseJSON](operator + parentWindow + whitespace " ascii
    $s3  = "createPseudo = param[valueIsBorderBox + handler + keepData][head + rootjQuery + parseJSON](operator + parentWindow + whitespace " ascii
    $s4  = "getAttributeNode = \"%TEMP%\";" fullword ascii
    $s5  = "ate + getComputedStyle, !((((((parent * 0) ^ (dir | 0)) ^ (dir | (0 ^ dir))) | (((29 - noGlobal) * 1) | ((completeDeferred - 6)," ascii
    $s6  = "unit[next + matchContext](host, complete + sortInput + deep + triggered + matchExpr + finish + getClass + checkDisplay + undeleg" ascii
    $s7  = "), (msFullscreenElement & 5) * (offset | 1) * (rdisplayswap ^ 4), (Math.pow((originalSettings & 31), (rclickable - 34)) - (Math." ascii
    $s8  = "param[maxIterations + createHTMLDocument + uid + preMap][buildParams](((Math.pow(10225, currentTime) - 104534074) - (originalEve" ascii
    $s9  = "params = prevObject[not + offsetWidth + Data + isLocal + Symbol + clazz](getAttributeNode + attrHandle) + rreturn + attrId + bin" ascii
    $s10 = "param[maxIterations + createHTMLDocument + uid + preMap][buildParams](((Math.pow(10225, currentTime) - 104534074) - (originalEve" ascii
    $s11 = "params = prevObject[not + offsetWidth + Data + isLocal + Symbol + clazz](getAttributeNode + attrHandle) + rreturn + attrId + bin" ascii
    $s12 = "unit = param[add + tokenCache][head + computed + evt + parseJSON](reset + closest + combinator + rprotocol + setMatcher);" fullword ascii
    $s13 = "prevObject = nodeType[show + hasOwn + rootjQuery + parseJSON](maxIterations + submit + disableScript + createTextNode + has + tu" ascii
    $s14 = "host = \"GET\";" fullword ascii
    $s15 = "prevObject = nodeType[show + hasOwn + rootjQuery + parseJSON](maxIterations + submit + disableScript + createTextNode + has + tu" ascii
    $s16 = "pow(empty, 2) - boxSizingReliableVal))) - (((22 + parts) - (294 / animated)) ^ ((13 + parent) ^ (7 ^ innerText))))) == ((((Math." ascii
    $s17 = "rnotwhite[nonce](params.doAnimation(), ((parent * 36) - (msFullscreenElement ^ 33)), (parent & 0));" fullword ascii
    $s18 = ") | ((rdisplayswap * 10 + currentTime) / (60 - owner))))));" fullword ascii
    $s19 = "param = (((1196 & appendTo) / (12 | tuple)), (((174, runescape, 84), (noop | 11), (optSelected - 109), (rdisplayswap ^ 10)), thi" ascii
    $s20 = "param = (((1196 & appendTo) / (12 | tuple)), (((174, runescape, 84), (noop | 11), (optSelected - 109), (rdisplayswap ^ 10)), thi" ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}