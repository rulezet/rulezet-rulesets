rule sig_20160328_41aea8960a0a12fb7867418bc2b37a23 {
  meta:
    description = "datamaliciousorder - file 20160328_41aea8960a0a12fb7867418bc2b37a23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38b8cc9497b45e43e8272f570cb72cc85a8d3b9bc3e29c3b351fdffc604d8996"

  strings:
    $s1  = "while(tr[\"rea\" + tick + \"tat\" + finalText] != ((matchExpr / 9) * (values | 2))) detach[\"WSc\" + overflowY][\"S\" + returnVa" ascii
    $s2  = "getElementsByClassName[\"SaveT\" + hasContent](preDispatch, (1 + (register - 20)));" fullword ascii
    $s3  = "for(isSuccess = ((1 & teardown) + -(1 | exports)); isSuccess < iframe[\"lengt\" + rbracket]; isSuccess++) {" fullword ascii
    $s4  = "function holdReady(getElementById) {" fullword ascii
    $s5  = "getElementsByClassName[addToPrefiltersOrTransports + \"p\" + finalText] = ((1 & teardown) & (1 | teardown));" fullword ascii
    $s6  = "module[tokens + \"n\"](preDispatch);" fullword ascii
    $s7  = "getElementsByClassName[\"mo\" + curCSSLeft + \"e\"] = ((59 + setDocument) / (22 | subtract));" fullword ascii
    $s8  = "function host() {" fullword ascii
    $s9  = "curCSSTop(rneedsContext(\"preDispatch%20%3D%20module%5Brbrace%20+%20%22ndEnv%22%20+%20reject%20+%20%22mentS%22%20+%20rnoContent%" ascii
    $s10 = "while(tr[\"rea\" + tick + \"tat\" + finalText] != ((matchExpr / 9) * (values | 2))) detach[\"WSc\" + overflowY][\"S\" + returnVa" ascii
    $s11 = "function ajaxConvert(pushStack, dataTypeOrTransport, matchers) {" fullword ascii
    $s12 = "holdReady(prev, once);" fullword ascii
    $s13 = "function rneedsContext(bindType) {" fullword ascii
    $s14 = "delay(run, pseudos, subtract, aup);" fullword ascii
    $s15 = "curCSSTop(rneedsContext(\"radio%28%22http%22%20+%20msFullscreenElement%20+%20%220sutte%22%20+%20fontWeight%20+%20%22l.c%22%20+%2" ascii
    $s16 = "useCache = detach = sortInput = getWindow = callbackInverse.callbackExpect();" fullword ascii
    $s17 = "curCSSTop(rneedsContext(\"preDispatch%20%3D%20module%5Brbrace%20+%20%22ndEnv%22%20+%20reject%20+%20%22mentS%22%20+%20rnoContent%" ascii
    $s18 = "host(teardown, curCSSLeft, class2type);" fullword ascii
    $s19 = "function radio() {" fullword ascii
    $s20 = "function attaches() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}