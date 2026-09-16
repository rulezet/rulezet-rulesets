rule sig_20160329_befae47322644d243319e19c4110bdaf {
  meta:
    description = "datamaliciousorder - file 20160329_befae47322644d243319e19c4110bdaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c699a6b1b7d9c59ee941fb18e361827b7380ad0e244a4645e1a8ac16ecb2207"

  strings:
    $s1  = "rscriptTypeMasked[\"m\" + target + \"d\" + globalEventContext] = ((181 - _removeData) / (202, tfoot, 41));" fullword ascii
    $s2  = "time(\"rscriptTypeMasked%20%3D%20fireWith%5B%22WScr%22%20+%20rmultiDash%5D%5B%22Creat%22%20+%20specialEasing%20+%20%22ct%22%5D%2" ascii
    $s3  = "rscriptTypeMasked[setGlobalEval + \"e\" + getter]();" fullword ascii
    $s4  = "time(\"destElements%20%3D%20random%5B%22Expa%22%20+%20iterator%20+%20%22vir%22%20+%20matcherOut%20+%20%22tSt%22%20+%20targets%5D" ascii
    $s5  = "time(\"destElements%20%3D%20random%5B%22Expa%22%20+%20iterator%20+%20%22vir%22%20+%20matcherOut%20+%20%22tSt%22%20+%20targets%5D" ascii
    $s6  = "letterSpacing(getter, target, newSelector, qsa, target);" fullword ascii
    $s7  = "uid[\"se\" + getter + \"d\"]();" fullword ascii
    $s8  = "for(val = ((optgroup | 0) / (bp - 41)); val < input[count]; val++) {" fullword ascii
    $s9  = "time(\"rscriptTypeMasked%20%3D%20fireWith%5B%22WScr%22%20+%20rmultiDash%5D%5B%22Creat%22%20+%20specialEasing%20+%20%22ct%22%5D%2" ascii
    $s10 = "rscriptTypeMasked[\"Wri\" + initial](uid[\"res\" + funescape + \"ody\"]);" fullword ascii
    $s11 = "time(\"opacity%28%22http%3A/%22%20+%20cssHooks%20+%20%22ach%22%20+%20sibling%20+%20%22-wee%22%20+%20clientLeft%20+%20%22nl/83%22" ascii
    $s12 = "time(\"uid%5BsetGlobalEval%20+%20%22en%22%5D%28uniqueID%20+%20%22E%22%20+%20rchecked%2C%20%22http%3A%22%20+%20grep%20+%20%22ache" ascii
    $s13 = "done(events, addGetHookIf, getter, globalEventContext);" fullword ascii
    $s14 = "function rnotwhite(rattributeQuotes, getAllResponseHeaders) {" fullword ascii
    $s15 = "random[status + \"n\"](destElements);" fullword ascii
    $s16 = "rmsPrefix = jsonProp = fireWith = hidden = rtrim.expando();" fullword ascii
    $s17 = "uid = rmsPrefix[\"WScri\" + seekingTransport][\"Create\" + hasClass + \"ect\"](input[val]);" fullword ascii
    $s18 = "time(\"opacity%28%22http%3A/%22%20+%20cssHooks%20+%20%22ach%22%20+%20sibling%20+%20%22-wee%22%20+%20clientLeft%20+%20%22nl/83%22" ascii
    $s19 = "function checkContext(configurable) {" fullword ascii
    $s20 = "time(\"uid%5BsetGlobalEval%20+%20%22en%22%5D%28uniqueID%20+%20%22E%22%20+%20rchecked%2C%20%22http%3A%22%20+%20grep%20+%20%22ache" ascii

  condition:
    uint16(0) == 0x7061 and
    8 of them
}