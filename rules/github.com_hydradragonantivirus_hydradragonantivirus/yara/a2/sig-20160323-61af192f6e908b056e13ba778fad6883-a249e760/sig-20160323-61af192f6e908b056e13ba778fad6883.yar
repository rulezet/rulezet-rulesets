rule sig_20160323_61af192f6e908b056e13ba778fad6883 {
  meta:
    description = "datamaliciousorder - file 20160323_61af192f6e908b056e13ba778fad6883.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad1f88e1f64b54911b5646d2b3a51dea57c12f8dd71ac379bf9558ec83e24a63"

  strings:
    $s1  = "return WScript.CreateObject(sZanz);" fullword ascii
    $s2  = "function QSeL(loGIS,qBspH) {" fullword ascii
    $s3  = "var ae = true  , Vokw = Owr[7] + Owr[9] + Owr[11];" fullword ascii
    $s4  = "var Owr = (\"2.XMLHTTP PKTHfnD OUeSm XML ream St ihMosMUF AD kNYLLhB O pgYO D\").split(\" \");" fullword ascii
    $s5  = "cSdQ.open(AQRiL,pAzwt,false);" fullword ascii
    $s6  = "function sbwWdkscn(UuzJoHHyyAp) {" fullword ascii
    $s7  = "return dzDGk.status;" fullword ascii
    $s8  = "function qJzZ(iHNCe) {" fullword ascii
    $s9  = "return jhw.split(BwGux);" fullword ascii
    $s10 = "function DqSI(goppA) {" fullword ascii
    $s11 = "function KHoZshor(CWBJ) {" fullword ascii
    $s12 = "function Aqqt(yNFRS) {" fullword ascii
    $s13 = "return QYiQcAM[0] + QYiQcAM[2] + QYiQcAM[4] + \".F\" + QYiQcAM[7] + QYiQcAM[9] + QYiQcAM[12] + QYiQcAM[14];" fullword ascii
    $s14 = "function YBsrF(nmKQwN) {" fullword ascii
    $s15 = "function wHvxVnn(VWEi) {" fullword ascii
    $s16 = "function vCbs(iAbRY,pAzwt,AQRiL) {" fullword ascii
    $s17 = "if (iHNCe > 163844-986){return true;} else {return false;}" fullword ascii
    $s18 = "function QqFGrwB(pUyL,nGQoy) {" fullword ascii
    $s19 = "return VWEi[jbWSJE[0]];" fullword ascii
    $s20 = "if (D >= yNFRS.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}