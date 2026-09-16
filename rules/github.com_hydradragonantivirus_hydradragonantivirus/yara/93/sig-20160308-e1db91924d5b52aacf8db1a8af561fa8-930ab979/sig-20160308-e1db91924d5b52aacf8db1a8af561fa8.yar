rule sig_20160308_e1db91924d5b52aacf8db1a8af561fa8 {
  meta:
    description = "datamaliciousorder - file 20160308_e1db91924d5b52aacf8db1a8af561fa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a93db6ead03d634712420608f47cf32100b599ae99b8206cea942a8ada678b7"

  strings:
    $s1  = "return htoCWiG[0] + htoCWiG[2] + htoCWiG[4] + \".F\" + htoCWiG[7] + htoCWiG[9] + htoCWiG[12] + htoCWiG[14];" fullword ascii
    $s2  = "var sT = true  , frtf = Jnf[7] + Jnf[9] + Jnf[11];" fullword ascii
    $s3  = "rNWMY.open(XAjAI,RnuZf,false);" fullword ascii
    $s4  = "var Jnf = (\"2.XMLHTTP nXqwnrH iOtNS XML ream St SnQPxywc AD BZYrtYZ O rprh D\").split(\" \");" fullword ascii
    $s5  = "if(y>=p.length) {break;}" fullword ascii
    $s6  = "return ArIfq;" fullword ascii
    $s7  = "HdF = y; break; " fullword ascii
    $s8  = "function AusR(rNWMY,RnuZf,XAjAI) {" fullword ascii
    $s9  = "function RPdT(VfZgD) {" fullword ascii
    $s10 = "function pQsz(gwHSo) {" fullword ascii
    $s11 = "return gou.size;" fullword ascii
    $s12 = "if (wjsGN == 987-787){return true;} else {return false;}" fullword ascii
    $s13 = "return YxnjiXg" fullword ascii
    $s14 = "function qMjL(ZHFFJ) {" fullword ascii
    $s15 = "function dLXOFMqU(gou) {" fullword ascii
    $s16 = "function yLQC(DKxTR,cwPSJ) {" fullword ascii
    $s17 = "function omGN(XPBZK) {" fullword ascii
    $s18 = "function FniAIDid() {" fullword ascii
    $s19 = "return ZHFFJ.status;" fullword ascii
    $s20 = "function aCKe(wjsGN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}