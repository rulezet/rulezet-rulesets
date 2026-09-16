rule sig_20160405_1a801cec29f17662db2de1c568825049 {
  meta:
    description = "datamaliciousorder - file 20160405_1a801cec29f17662db2de1c568825049.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c012acb3a8b5b5a779f7266bb1705d49d5caad19df0b792cbfd79ca2a721fd8"

  strings:
    $s1  = "return uDKuAyk[0] + uDKuAyk[2] + uDKuAyk[4] + \".F\" + uDKuAyk[7] + uDKuAyk[9] + uDKuAyk[12] + uDKuAyk[14];" fullword ascii
    $s2  = "var II = true  , vaal = hpw[7] + hpw[9] + hpw[11];" fullword ascii
    $s3  = "var hpw = (\"2.XMLHTTP OZUHuxS TOSIs XML ream St FvEiUQww AD vBwwxjx O FXFJ D\").split(\" \");" fullword ascii
    $s4  = "BNUw.open(mokeT,YDrYG,false);" fullword ascii
    $s5  = "return Kne.size;" fullword ascii
    $s6  = "function DBTv(AcQwd,qRNCf) {" fullword ascii
    $s7  = "Cxb = r; break; " fullword ascii
    $s8  = "function VPGVGy(DnQlApQ) {" fullword ascii
    $s9  = "function rJFGV(pZZGXe) {" fullword ascii
    $s10 = "function Jeba(kNLzZ) {" fullword ascii
    $s11 = "if (VDRDC == 1024-824){return true;} else {return false;}" fullword ascii
    $s12 = "if (AhLwe > 181983-839){return true;} else {return false;}" fullword ascii
    $s13 = "function QGelXNNMx(nRPif) {" fullword ascii
    $s14 = "function GmpC(Kxsze) {" fullword ascii
    $s15 = "function JMkE(Avxue,YDrYG,mokeT) {" fullword ascii
    $s16 = "return txqbNwL;" fullword ascii
    $s17 = "function vBSLKy(kJBF,xnWaAa) {" fullword ascii
    $s18 = "function eSWU(SZyfj) {" fullword ascii
    $s19 = "return Qmc.split(ZGnJl);" fullword ascii
    $s20 = "function onqMubrW(Kne) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}