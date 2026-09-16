rule sig_20160309_c70a25ae86a12e74197850f91c29b87d {
  meta:
    description = "datamaliciousorder - file 20160309_c70a25ae86a12e74197850f91c29b87d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbde0b4d9ccc314333ad367a7d9b70196c00e7629c6e783bffa635b400807bb6"

  strings:
    $s1  = "var RV = true  , OnWp = MYI[7] + MYI[9] + MYI[11];" fullword ascii
    $s2  = "return pLDignh[0] + pLDignh[2] + pLDignh[4] + \".F\" + pLDignh[7] + pLDignh[9] + pLDignh[12] + pLDignh[14];" fullword ascii
    $s3  = "var pLDignh = \"Sc cVuBooJ r IygOjGqDu ipting oLUXnFX PSD ile lxrasoEioMDpJF System Il oCWgh Obj jChoAU ect oTsgQlw\".split(\" " ascii
    $s4  = "var MYI = (\"2.XMLHTTP hyROemO eeDAH XML ream St vbECThkp AD yvUIRiC O ffZD D\").split(\" \");" fullword ascii
    $s5  = "Rxths.open(jLxeQ,stnlp,false);" fullword ascii
    $s6  = "return hRLVi.status;" fullword ascii
    $s7  = "function Dzdd(dVRiQ,vWeha) {" fullword ascii
    $s8  = "if (G >= GpASo.length) {break;}" fullword ascii
    $s9  = "function fBULjup(yzCf,EowWa) {" fullword ascii
    $s10 = "function azLiIsVpN(RQToe,aooVK,ZFqJg,EYDQ) {" fullword ascii
    $s11 = "return new ActiveXObject(twaHoE);" fullword ascii
    $s12 = "function QBUS(DgqRG) {" fullword ascii
    $s13 = "function HFwc(hRLVi) {" fullword ascii
    $s14 = "function iFef(zgKkx) {" fullword ascii
    $s15 = "function tjsr(lvLxN) {" fullword ascii
    $s16 = "function sJptKQvA(YMk) {" fullword ascii
    $s17 = "function ZIJO(GpASo) {" fullword ascii
    $s18 = "function wvqnisFB(NCdri,Uhekpx) {" fullword ascii
    $s19 = "function znLNDYbxA(sqaHWiFQZqH) {" fullword ascii
    $s20 = "ljn = l; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}