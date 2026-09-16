rule sig_20160328_71632ec0c55f5b7c60e3b77a11f5be44 {
  meta:
    description = "datamaliciousorder - file 20160328_71632ec0c55f5b7c60e3b77a11f5be44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff1c12cd6cd3405865283b1f418e6f1b045e5f05d612f7f9ece1fa33a39df74"

  strings:
    $s1  = "while(attrHooks[\"readyS\" + parse + \"e\"] != ((4 | invert) | 0)) newDefer[fixHook + \"ipt\"][processData + \"le\" + insertAfte" ascii
    $s2  = "while(attrHooks[\"readyS\" + parse + \"e\"] != ((4 | invert) | 0)) newDefer[fixHook + \"ipt\"][processData + \"le\" + insertAfte" ascii
    $s3  = "postFilter[propHooks + \"y\" + wait + \"e\"] = ((912 / trigger) / (133 - getter));" fullword ascii
    $s4  = "postFilter[\"Wr\" + docElem](attrHooks[\"respon\" + compile + \"ody\"]);" fullword ascii
    $s5  = "for(beforeSend = ((Math.pow(103, display) - 10424), (dataType - 44), (unit / 8), invert); beforeSend < elems[position + \"th\"];" ascii
    $s6  = "for(beforeSend = ((Math.pow(103, display) - 10424), (dataType - 44), (unit / 8), invert); beforeSend < elems[position + \"th\"];" ascii
    $s7  = "postFilter[args + \"de\"] = ((1 * clearCloneStyle) + (0 | invert));" fullword ascii
    $s8  = "if(attrHooks[bulk + \"us\"] == ((inspected - 3988) / (mouseleave, 89, text, 47))) {" fullword ascii
    $s9  = "(((active), (5580 / readyState), (12 * text + 4)));" fullword ascii
    $s10 = "function getElementById(implementation) {" fullword ascii
    $s11 = "function postFinder(replaceAll, defaultValue, nodeName) {" fullword ascii
    $s12 = "function unwrap(contents) {" fullword ascii
    $s13 = "getElementById(attrHandle, which, not, rcheckableType, file);" fullword ascii
    $s14 = "isXML[promise + \"n\"](mouseHooks);" fullword ascii
    $s15 = "unwrap(off, dataType, matcherFromTokens, contextBackup);" fullword ascii
    $s16 = "handleObj(rdashAlpha, returnFalse, readyState, firing);" fullword ascii
    $s17 = "rigger%20%3D%20%2819%29%3Bvar%20divStyle%20%3D%20%284%29%2C%20docElem%20%3D%20%28%22ite%22%29%2C%20propHooks%20%3D%20%28%22t%22%" ascii
    $s18 = "function handleObj(offset, animate) {" fullword ascii
    $s19 = "fixInput(fixHook, ignored, returnFalse, file);" fullword ascii
    $s20 = "container();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}