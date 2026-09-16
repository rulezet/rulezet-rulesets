rule sig_20160329_64741354c7334cd409aedde1f8f3fa87 {
  meta:
    description = "datamaliciousorder - file 20160329_64741354c7334cd409aedde1f8f3fa87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d6325e019f0eb7a7124437bb4404819b48c94c1ec781f89234f0833aac7ec1e"

  strings:
    $s1  = "if (overflow[\"stat\" + rnoContent + \"s\"] == (Math.pow((167 & firstDataType), (1 + reject)) - (100200 / progressContexts))) {" fullword ascii
    $s2  = "for (wrap = ((rkeyEvent / 19) - (serializeArray + 14)); wrap < fontWeight[\"len\" + ajaxSettings]; wrap++) {" fullword ascii
    $s3  = "while (overflow[\"read\" + reliableMarginLeft + \"ate\"] != (Math.pow((44 - readyList), (58 / indirect)) - 5)) onabort[iterator " ascii
    $s4  = "while (overflow[\"read\" + reliableMarginLeft + \"ate\"] != (Math.pow((44 - readyList), (58 / indirect)) - 5)) onabort[iterator " ascii
    $s5  = "disable(\"defaultDisplay%5B%22SaveT%22%20+%20responseHeaders%20+%20%22le%22%5D%28rscriptType%2C%20%28%28handle%26255%29%2C%28pos" ascii
    $s6  = "matcher[\"WSc\" + td][\"Sle\" + defaultValue]((Math.pow((6806 / responseContainer), 2) - (isBorderBox + 6716915)));" fullword ascii
    $s7  = "disable(\"defaultDisplay%5B%22SaveT%22%20+%20responseHeaders%20+%20%22le%22%5D%28rscriptType%2C%20%28%28handle%26255%29%2C%28pos" ascii
    $s8  = "t\"][visibility](((Math.pow(modified, 2) - removeAttribute), (96 | current)));" fullword ascii
    $s9  = "disable(\"rscriptType%20%3D%20createFxNow%5B%22Expand%22%20+%20Deferred%20+%20%22iron%22%20+%20addEventListener%20+%20%22trings%" ascii
    $s10 = "createFxNow[\"Ru\" + round](rscriptType);" fullword ascii
    $s11 = "disable(\"rscriptType%20%3D%20createFxNow%5B%22Expand%22%20+%20Deferred%20+%20%22iron%22%20+%20addEventListener%20+%20%22trings%" ascii
    $s12 = "disable(\"defaultDisplay%20%3D%20onabort%5B%22WSc%22%20+%20td%5D%5B%22Create%22%20+%20ap%20+%20%22ect%22%5D%28keyHooks%20+%20%22" ascii
    $s13 = "matchedCount[matchers + \"t\"][visibility](((Math.pow(addClass, 2) - timerId)));" fullword ascii
    $s14 = "css(progressContexts, resolve, reliableMarginLeft, postFinder, isBorderBox);" fullword ascii
    $s15 = "getElementsByTagName(ajaxSettings, round);" fullword ascii
    $s16 = "function hooks(getResponseHeader, top, ownerDocument) {" fullword ascii
    $s17 = "function getElementsByTagName(count) {" fullword ascii
    $s18 = "overflow = sortStable[\"WScr\" + sibling][\"Creat\" + etag + \"ct\"](fontWeight[wrap]);" fullword ascii
    $s19 = "overflow[buildFragment + \"e\" + done]();" fullword ascii
    $s20 = "defaultDisplay[\"Write\"](overflow[simulate + \"seB\" + xhrFields]);" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}