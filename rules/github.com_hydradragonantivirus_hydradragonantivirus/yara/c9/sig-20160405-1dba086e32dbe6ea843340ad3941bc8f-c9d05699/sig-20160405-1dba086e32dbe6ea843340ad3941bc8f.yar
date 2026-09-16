rule sig_20160405_1dba086e32dbe6ea843340ad3941bc8f {
  meta:
    description = "datamaliciousorder - file 20160405_1dba086e32dbe6ea843340ad3941bc8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfdbf42a6ac6732a2196626b7614dc261017d896663ec0887b64b00f04f2ce72"

  strings:
    $s1  = "return pHbAlSB[0] + pHbAlSB[2] + pHbAlSB[4] + \".F\" + pHbAlSB[7] + pHbAlSB[9] + pHbAlSB[12] + pHbAlSB[14];" fullword ascii
    $s2  = "var LG = true  , WBRk = HIp[7] + HIp[9] + HIp[11];" fullword ascii
    $s3  = "var HIp = (\"2.XMLHTTP ZSYErmv VZxAd XML ream St AtjXsvuG AD jljNaDV O zsTe D\").split(\" \");" fullword ascii
    $s4  = "var sQFiIaK = \"fbPlbm*HTd*pt.S\"+\"hell*MvPRmIE*Scri*\";" fullword ascii
    $s5  = "function zcXm(ELesO) {" fullword ascii
    $s6  = "function NBLQ(ruZTH,eajvm) {" fullword ascii
    $s7  = "function HUNK(JsPNA) {" fullword ascii
    $s8  = "return new ActiveXObject(oBRb);" fullword ascii
    $s9  = "function mhHdiLMpr(hybdC) {" fullword ascii
    $s10 = "function zPZRzbbv(aGun) {" fullword ascii
    $s11 = "function QUWB(LpfIO,AeMli) {" fullword ascii
    $s12 = "function NwHA(maCIB) {" fullword ascii
    $s13 = "return bZG.size;" fullword ascii
    $s14 = "function uaoX(wqwYO) {" fullword ascii
    $s15 = "function Gjzk(QoPMg) {" fullword ascii
    $s16 = "return vMIWprz[0];" fullword ascii
    $s17 = "function MKXsw(CxF,YCURb) {" fullword ascii
    $s18 = "return uyRQ;" fullword ascii
    $s19 = "return CxF.split(YCURb);" fullword ascii
    $s20 = "function Drhui(aBToOD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}