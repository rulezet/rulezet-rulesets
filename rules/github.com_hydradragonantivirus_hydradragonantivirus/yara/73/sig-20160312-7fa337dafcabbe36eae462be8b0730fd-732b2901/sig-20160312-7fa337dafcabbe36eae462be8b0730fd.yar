rule sig_20160312_7fa337dafcabbe36eae462be8b0730fd {
  meta:
    description = "datamaliciousorder - file 20160312_7fa337dafcabbe36eae462be8b0730fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7217a5ae218bfe2a7693c546288b65145d5d8bef198d98d6a25f7701b5e8560"

  strings:
    $s1  = "return vwUEFEi[0] + vwUEFEi[2] + vwUEFEi[4] + \".F\" + vwUEFEi[7] + vwUEFEi[9] + vwUEFEi[12] + vwUEFEi[14];" fullword ascii
    $s2  = "var KL = true  , QoBv = GjJ[7] + GjJ[9] + GjJ[11];" fullword ascii
    $s3  = "BNXVr.open(lIfrV,KACXZ,false);" fullword ascii
    $s4  = "var GjJ = (\"2.XMLHTTP vGNAXKc eBUfO XML ream St zDeNkOVD AD luNALxC O QMaU D\").split(\" \");" fullword ascii
    $s5  = "var vwUEFEi = \"Sc arUatlu r SXyiRDyKd ipting MRtnDeL rZE ile txdzIKFfESydtu System ui gZIbY Obj ZUxaQP ect NGarMyL\".split(\" " ascii
    $s6  = "return uwVRm;" fullword ascii
    $s7  = "function gVIOIPh(VIuh) {" fullword ascii
    $s8  = "if(w>=F.length) {break;}" fullword ascii
    $s9  = "return VIuh.responseBody;" fullword ascii
    $s10 = "function PFhV(eyhDB) {" fullword ascii
    $s11 = "function OQfy(QRhVQ,SFhHT) {" fullword ascii
    $s12 = "if (b >= NxiGr.length) {break;}" fullword ascii
    $s13 = "return mRApoCS(Am,jllbk[294-288]+jllbk[215-208]+jllbk[285-277]);" fullword ascii
    $s14 = "return HHVag.status;" fullword ascii
    $s15 = "return wIPMBL.position=357-357;" fullword ascii
    $s16 = "return Ykp.size;" fullword ascii
    $s17 = "function ldel(RXspf) {" fullword ascii
    $s18 = "function mRApoCS(GBJL,tavAb) {" fullword ascii
    $s19 = "function BqrY(NxiGr) {" fullword ascii
    $s20 = "if (ALtnA > 154652-674){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}