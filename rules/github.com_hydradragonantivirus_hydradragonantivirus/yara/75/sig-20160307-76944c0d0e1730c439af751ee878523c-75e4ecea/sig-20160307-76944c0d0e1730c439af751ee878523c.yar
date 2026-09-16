rule sig_20160307_76944c0d0e1730c439af751ee878523c {
  meta:
    description = "datamaliciousorder - file 20160307_76944c0d0e1730c439af751ee878523c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c90b9c7cf84e0e1cfbff32aa7d65723786b144b65bb3854ce647b99ce1ea354"

  strings:
    $s1  = "var yP = true  , tHYF = JZL[7] + JZL[9] + JZL[11];" fullword ascii
    $s2  = "return fHgggWv[0] + fHgggWv[2] + fHgggWv[4] + \".F\" + fHgggWv[7] + fHgggWv[9] + fHgggWv[12] + fHgggWv[14];" fullword ascii
    $s3  = "albHO.open(tSLpp,rHJyO,false);" fullword ascii
    $s4  = "var fHgggWv = \"Sc pXQLMuo r xSxXMQSvX ipting MmgWXGR WRN ile OYyFgOrfraukAP System VD bzaRm Obj AHalgU ect BUonMqa\".split(\" " ascii
    $s5  = "var JZL = (\"2.XMLHTTP NAaXlos kzqBk XML ream St ViEZQKbB AD RhgzVoe O YMrY D\").split(\" \");" fullword ascii
    $s6  = "if(c>=A.length) {break;}" fullword ascii
    $s7  = "function TVZq(FJPlL) {" fullword ascii
    $s8  = "function xcXP(uvOzl) {" fullword ascii
    $s9  = "if (XQqBu == 414-214){return true;} else {return false;}" fullword ascii
    $s10 = "function rMORI(eYdzEe) {" fullword ascii
    $s11 = "function fEJt(XQqBu) {" fullword ascii
    $s12 = "GEAr(BPL); BPL.type = 1; JxHo(BPL,gpJCgDd(xH)); if (URVZ(tTHkiRqz(BPL)))  {" fullword ascii
    $s13 = "function TMta(albHO,rHJyO,tSLpp) {" fullword ascii
    $s14 = "function tTHkiRqz(bVx) {" fullword ascii
    $s15 = "function URVZ(usfEn) {" fullword ascii
    $s16 = "return qFJFP;" fullword ascii
    $s17 = "function gpJCgDd(rVkx) {" fullword ascii
    $s18 = "if (((new Date())>0,7969369888)) {" fullword ascii
    $s19 = "function dJsW(JNNgk) {" fullword ascii
    $s20 = "return biTftGr" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}