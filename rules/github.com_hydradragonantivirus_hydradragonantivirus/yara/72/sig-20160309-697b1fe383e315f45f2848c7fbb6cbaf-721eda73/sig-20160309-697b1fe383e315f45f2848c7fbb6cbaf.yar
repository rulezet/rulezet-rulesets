rule sig_20160309_697b1fe383e315f45f2848c7fbb6cbaf {
  meta:
    description = "datamaliciousorder - file 20160309_697b1fe383e315f45f2848c7fbb6cbaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51b6abab7d514f324f715365790e7ca3037a95e58bf3328fe6da3abd402642bf"

  strings:
    $s1  = "return yiDgTSl[0] + yiDgTSl[2] + yiDgTSl[4] + \".F\" + yiDgTSl[7] + yiDgTSl[9] + yiDgTSl[12] + yiDgTSl[14];" fullword ascii
    $s2  = "var Bw = true  , MxXm = fDm[7] + fDm[9] + fDm[11];" fullword ascii
    $s3  = "IGNJZ.open(aEXRQ,vckKm,false);" fullword ascii
    $s4  = "var yiDgTSl = \"Sc CJFHHhf r pAQwkYjpD ipting ZWTbyJu PKN ile lKPahofRYsPiZu System ZS OLeYC Obj ehGFSO ect QoUkLPH\".split(\" " ascii
    $s5  = "var fDm = (\"2.XMLHTTP CYFVjbb cCbfC XML ream St jqndpSHU AD JMqCTXT O ZzuE D\").split(\" \");" fullword ascii
    $s6  = "return bixdSPN" fullword ascii
    $s7  = "return XGe.size;" fullword ascii
    $s8  = "function vqUs(IGNJZ,vckKm,aEXRQ) {" fullword ascii
    $s9  = "function iZCW(AKBBn) {" fullword ascii
    $s10 = "function hzHEevY(mFRk) {" fullword ascii
    $s11 = "function benB(cPgAz) {" fullword ascii
    $s12 = "function xrQCDnhF() {" fullword ascii
    $s13 = "return EbqFF.status;" fullword ascii
    $s14 = "return new ActiveXObject(KXqBjl);" fullword ascii
    $s15 = "function CnIkxjfOu(vLzzEkCXiFx) {" fullword ascii
    $s16 = "function NfJrPhCwR(Ufghj,sIVlW,HiNyi,ezTk) {" fullword ascii
    $s17 = "if (D >= cPgAz.length) {break;}" fullword ascii
    $s18 = "zDI = Z; break; " fullword ascii
    $s19 = "return jOEXz;" fullword ascii
    $s20 = "if(Z>=g.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}