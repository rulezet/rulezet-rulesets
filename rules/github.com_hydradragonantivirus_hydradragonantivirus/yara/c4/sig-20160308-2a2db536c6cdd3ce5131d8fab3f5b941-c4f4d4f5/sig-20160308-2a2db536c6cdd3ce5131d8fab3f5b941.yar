rule sig_20160308_2a2db536c6cdd3ce5131d8fab3f5b941 {
  meta:
    description = "datamaliciousorder - file 20160308_2a2db536c6cdd3ce5131d8fab3f5b941.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1b4b44cdcf2e342a2400417d03b652be3d104e1553287898ef6070dda5df32d"

  strings:
    $x1  = "toSelector[lastModified](fromCharCode, targets + adown + xhrSuccessStatus + thead + parent + timers + pixelMarginRight, !(8 < (M" ascii
    $s2  = "firing = unit[camelKey + find + getResponseHeader + run + num + textContent + bind + matcherFromTokens](r20 + step + ajaxPrefilt" ascii
    $s3  = "firing = unit[camelKey + find + getResponseHeader + run + num + textContent + bind + matcherFromTokens](r20 + step + ajaxPrefilt" ascii
    $s4  = "Math.pow(19, getAttributeNode) - 336) - (reset ^ 6))) - (parseFromString - (2770 - ownerDocument))), (((11 ^ href) / (94 - multi" ascii
    $s5  = "pleContexts)) ^ (3 & checkOn)))) - (Math.pow((((36 - maxIterations) ^ (0 / responseHeadersString)) + ((11 - high) ^ (2 | fast)))" ascii
    $s6  = "toSelector = oldCallbacks[createTween + overrideMimeType][hold + getJSON + timeoutTimer + subtract](script + ready + ajaxSetting" ascii
    $s7  = "toSelector = oldCallbacks[createTween + overrideMimeType][hold + getJSON + timeoutTimer + subtract](script + ready + ajaxSetting" ascii
    $s8  = "pts))), ((Math.pow(37 * getAttributeNode, (2 + getAttribute)) - (Math.pow(3922, getAttributeNode) - 15376695)) + ((fragment + 3)" ascii
    $s9  = " ^ (prototype * 4 + getAttributeNode))), (Math.pow((1 ^ getAttributeNode) * (15 - getAttributeNode) * (4 / getAttributeNode), ((" ascii
    $s10 = "ath.pow(((((dataFilter * 6 + attaches) & 89 * getAttributeNode), ((16 | fragment) * (1 ^ cssProps) + (2 * getAttributeNode)), (M" ascii
    $s11 = "ow(((pipe, 128, createComment) ^ (13 ^ createCache)), ((1 * getAttributeNode) & 3)) - ((node & 16174) ^ (opener * 2 + handlers))" ascii
    $s12 = "oldCallbacks[finish + xhrSupported][soFar](((Math.pow(850, getAttributeNode) - 721000) / (attaches + 1)));" fullword ascii
    $s13 = "toSelector[lastModified](fromCharCode, targets + adown + xhrSuccessStatus + thead + parent + timers + pixelMarginRight, !(8 < (M" ascii
    $s14 = "ath.pow(83, (prev / 27)) - (notifyWith / 8)), ((write / 40) & (cssProps & 6))) | ((clientY - (13 + udataOld)) - ((0 / isXMLDoc) " ascii
    $s15 = ", ((2 * getAttributeNode * 2 * high * 2 * getAttributeNode * 7 * getAttributeNode / 40) / ((high + 4) ^ checkOn * 7))) - (Math.p" ascii
    $s16 = "matcherFromGroupMatchers[curCSS](firing.attrHandle(), ((1 * getAttribute) ^ (0 / fast)), ((47 - optall)));" fullword ascii
    $s17 = "container = 28323, textContent = \"tS\", send = \"ri\", reset = 17, hasScripts = 802147627;" fullword ascii
    $s18 = "reliableMarginRight[rtypenamespace + state + clearQueue](firing, ((fragment * 1) * getAttributeNode));" fullword ascii
    $s19 = "forward[swap + rdisplayswap + charset] = ((multipleContexts, 46, rmouseEvent, 0) / (overflowX / 19));" fullword ascii
    $s20 = "while(toSelector[rquery + fire + subtract + rneedsContext] < ((0 | cssProps) | (0 ^ getAttribute))) {" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    1 of ($x*) and 4 of them
}