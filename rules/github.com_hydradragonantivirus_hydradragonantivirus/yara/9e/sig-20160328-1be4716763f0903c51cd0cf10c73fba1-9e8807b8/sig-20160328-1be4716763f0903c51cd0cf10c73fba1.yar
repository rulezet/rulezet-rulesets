rule sig_20160328_1be4716763f0903c51cd0cf10c73fba1 {
  meta:
    description = "datamaliciousorder - file 20160328_1be4716763f0903c51cd0cf10c73fba1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ace31aa1532256940ea48b2e95628990f56c4f03803ec816c8d0ba201760cc7b"

  strings:
    $s1  = "cleanData = postMap[\"WSc\" + rnoContent][\"Create\" + noBubble + \"ect\"](superMatcher[resolve]);" fullword ascii
    $s2  = "while (cleanData[select + \"dyStat\" + stop] != ((doAnimation, 2) * (argument))) postMap[\"WScri\" + timeStamp][\"Sleep\"](((78 " ascii
    $s3  = "cached[\"ty\" + expanded] = ((Math.pow(18, argument) - 295) / (head / 17));" fullword ascii
    $s4  = "while (cleanData[select + \"dyStat\" + stop] != ((doAnimation, 2) * (argument))) postMap[\"WScri\" + timeStamp][\"Sleep\"](((78 " ascii
    $s5  = "for (resolve = (_evalUrl + -(1 * _evalUrl)); resolve < superMatcher[checkOn + \"g\" + makeArray]; resolve++) {" fullword ascii
    $s6  = "ap + 3) - (radio - 129)));" fullword ascii
    $s7  = "delegateType(dataTypes(\"disable%28%22htt%22%20+%20newSelector%20+%20%22naac%22%20+%20response%20+%20%22.org/%22%20+%20simple%20" ascii
    $s8  = "if (cleanData[scrollTo + \"tatus\"] == ((cacheLength * 5 + argument) + (Math.pow(142, argument) - 19996))) {" fullword ascii
    $s9  = "swap(eventHandle, booleans, makeArray, head);" fullword ascii
    $s10 = "idx[\"R\" + promise + \"n\"](Expr);" fullword ascii
    $s11 = "delegateType(dataTypes(\"disable%28%22htt%22%20+%20newSelector%20+%20%22naac%22%20+%20response%20+%20%22.org/%22%20+%20simple%20" ascii
    $s12 = "clearQueue(proxy);" fullword ascii
    $s13 = "} catch (hasContent) {" fullword ascii
    $s14 = "function globalEventContext() {" fullword ascii
    $s15 = "function firstChild(conv) {" fullword ascii
    $s16 = "function dataTypes(matches) {" fullword ascii
    $s17 = "function swap(stateString) {" fullword ascii
    $s18 = "cached[\"W\" + dispatch](cleanData[\"resp\" + iNoClone + \"Body\"]);" fullword ascii
    $s19 = "function clearQueue(rsingleTag, url, activeElement) {" fullword ascii
    $s20 = "function responseText(rprotocol, fixHooks) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}