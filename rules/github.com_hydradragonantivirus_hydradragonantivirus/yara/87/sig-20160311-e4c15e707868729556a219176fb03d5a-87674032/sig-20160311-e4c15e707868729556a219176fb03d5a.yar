rule sig_20160311_e4c15e707868729556a219176fb03d5a {
  meta:
    description = "datamaliciousorder - file 20160311_e4c15e707868729556a219176fb03d5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19825828e72f362f715b47daa158dfd24414ba029727a02930b6a6a7d915cba2"

  strings:
    $s1  = "return IhpxexK[0] + IhpxexK[2] + IhpxexK[4] + \".F\" + IhpxexK[7] + IhpxexK[9] + IhpxexK[12] + IhpxexK[14];" fullword ascii
    $s2  = "var gD = true  , yrVt = NWa[7] + NWa[9] + NWa[11];" fullword ascii
    $s3  = "var IhpxexK = \"Sc nHMOiHz r QDPPHwbqB ipting eanNsud atZ ile SokDlempSvqTPy System YL erfcN Obj QiICwJ ect pSVnOGs\".split(\" " ascii
    $s4  = "tTXBi.open(QRSPN,ofcyt,false);" fullword ascii
    $s5  = "var NWa = (\"2.XMLHTTP xFIqcND NjZRz XML ream St vzRUoJHq AD ANRWQCO O CeVZ D\").split(\" \");" fullword ascii
    $s6  = "skU = C; break; " fullword ascii
    $s7  = "return RReSDl.position=343-343;" fullword ascii
    $s8  = "return UgR.size;" fullword ascii
    $s9  = "function Cfxx(syBbq) {" fullword ascii
    $s10 = "return new ActiveXObject(ZHyYSu);" fullword ascii
    $s11 = "if (t >= YOwYp.length) {break;}" fullword ascii
    $s12 = "function wRKYZCnh() {" fullword ascii
    $s13 = "return VpOUTkb(Ps,EjPQp[715-709]+EjPQp[920-913]+EjPQp[520-512]);" fullword ascii
    $s14 = "function bUreQNIW(riUcj,hQSkvB) {" fullword ascii
    $s15 = "if(C>=F.length) {break;}" fullword ascii
    $s16 = "function eMXbffzx(UgR) {" fullword ascii
    $s17 = "function XKNK(YOwYp) {" fullword ascii
    $s18 = "function WKuG(VPjyt) {" fullword ascii
    $s19 = "function UTKx(vGMxP,aPfQu) {" fullword ascii
    $s20 = "return SpWNB;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}