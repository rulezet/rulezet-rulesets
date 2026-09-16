rule sig_20160329_3391879ce1a25a0ad4b900eab18b577f {
  meta:
    description = "datamaliciousorder - file 20160329_3391879ce1a25a0ad4b900eab18b577f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d1c29a9a69c29ba385da69042a314d213a9295929f10839f5effadffda55c27"

  strings:
    $s1  = "extend[username + \"eToFil\" + setup](addBack, ((62 & currentTarget) / 31));" fullword ascii
    $s2  = "rquickExpr(getAll, rts, processData, interval);" fullword ascii
    $s3  = "bup(refElements, holdReady, processData, duration);" fullword ascii
    $s4  = "condense(holdReady, dequeue, linear, getAll, holdReady);" fullword ascii
    $s5  = "function contentDocument(replaceChild, compareDocumentPosition, isDefaultPrevented) {" fullword ascii
    $s6  = "extend[\"t\" + readyWait + \"pe\"] = (createFxNow & 1);" fullword ascii
    $s7  = "rscriptTypeMasked(unwrap, second, holdReady, restoreScript);" fullword ascii
    $s8  = "function rscriptTypeMasked(jqXHR, random, overflow) {" fullword ascii
    $s9  = "pageYOffset(\"extend%20%3D%20iframe%5Btweener%20+%20%22pt%22%5D%5BprevAll%20+%20%22eOb%22%20+%20refElements%5D%28%22ADO%22%20+%2" ascii
    $s10 = "extend[\"op\" + setup + \"n\"]();" fullword ascii
    $s11 = "rmouseEvent(linear, rtrim, isLocal, returnValue, postFinder);" fullword ascii
    $s12 = "ped) * (2 * interval + 1) * interval)) {" fullword ascii
    $s13 = "if (tweeners[\"statu\" + replaceWith] == ((2 + isImmediatePropagationStopped) * (5 & radioValue) * (2 + isImmediatePropagationSt" ascii
    $s14 = "function contextBackup(complete) {" fullword ascii
    $s15 = "pageYOffset(\"extend%20%3D%20iframe%5Btweener%20+%20%22pt%22%5D%5BprevAll%20+%20%22eOb%22%20+%20refElements%5D%28%22ADO%22%20+%2" ascii
    $s16 = "function binary(curPosition, gotoEnd, cssExpand) {" fullword ascii
    $s17 = "body(readyWait);" fullword ascii
    $s18 = "function rmouseEvent(rquery, finalText, keys) {" fullword ascii
    $s19 = "binary(_evalUrl, createFxNow, defaultExtra);" fullword ascii
    $s20 = "function rquickExpr() {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}