rule sig_20160419_0ca3e4cd8089e7128e4ce9d4a27f9965 {
  meta:
    description = "datamaliciousorder - file 20160419_0ca3e4cd8089e7128e4ce9d4a27f9965.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5be5f7d2a71bd5496c1f7887c13f3cdb25286e9d5023bcafb9bd831ae3c0b052"

  strings:
    $s1  = "return AVbnAuG[0] + AVbnAuG[2] + AVbnAuG[4] + \".F\" + AVbnAuG[7] + AVbnAuG[9] + AVbnAuG[12] + AVbnAuG[14];" fullword ascii
    $s2  = "var tn = true  , neGo = vqi[7] + vqi[9] + vqi[11];" fullword ascii
    $s3  = "var vqi = (\"2.XMLHTTP vBMakJv qSJWd XML ream St XXRIjaNe AD XnBbxBy O YrIT D\").split(\" \");" fullword ascii
    $s4  = "hBLK.open(YHRMH,rDttP,false);" fullword ascii
    $s5  = "if(c>=x.length) {break;}" fullword ascii
    $s6  = "function UvmCPF(MsJZsqd) {" fullword ascii
    $s7  = "function hhdI(TlSyI,dDzfr) {" fullword ascii
    $s8  = "if (YCPRV != 483-283){return false;} else {return true;}" fullword ascii
    $s9  = "function iaZZ(jyUME) {" fullword ascii
    $s10 = "if (h >= PYUxk.length) {break;}" fullword ascii
    $s11 = "function eiMuKfQM(QuT) {" fullword ascii
    $s12 = "function hHecs(lEf,SPxid) {" fullword ascii
    $s13 = "return QuT.size;" fullword ascii
    $s14 = "function WUlv(BjyDL) {" fullword ascii
    $s15 = "function eXdXNbug(YzTV) {" fullword ascii
    $s16 = "function BUdNLZYzX(gyNCxIOrfcU) {" fullword ascii
    $s17 = "return pKfzPwy;" fullword ascii
    $s18 = "return Gvforf[yAvP[103-103]]=243-243;" fullword ascii
    $s19 = "function mTRL(mkmxN) {" fullword ascii
    $s20 = "function hzoR(KVXii) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}