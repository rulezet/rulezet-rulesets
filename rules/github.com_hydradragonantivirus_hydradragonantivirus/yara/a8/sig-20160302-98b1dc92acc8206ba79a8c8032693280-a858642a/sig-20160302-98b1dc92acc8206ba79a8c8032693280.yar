rule sig_20160302_98b1dc92acc8206ba79a8c8032693280 {
  meta:
    description = "datamaliciousorder - file 20160302_98b1dc92acc8206ba79a8c8032693280.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f94b05414b6906bebc78a2402e7e48128e0d26c84db92ddc64a09e00762e04f1"

  strings:
    $s1  = "var qS = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(VyyNO);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + sPzdzNU + \".F\" + UwvEkHLobJ + eVjXO + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var pYV = (KiG + \"TTP\" + \" OmBfaZw cQatR XML ream St Uwoaqtwy AD HgRfXwA OD\").split(\" \");" fullword ascii
    $s5  = "var lX = true  , ZERN = pYV[7] + \"\" + pYV[9];" fullword ascii
    $s6  = "ecHUb.open(rrNCz,BrMjS,false);" fullword ascii
    $s7  = "function UuPh(gyPBs) {" fullword ascii
    $s8  = "if (VyZGM == 521-321){return true;} else {return false;}" fullword ascii
    $s9  = "function RajL(VyyNO) {" fullword ascii
    $s10 = "if(t>=v.length) {break;}" fullword ascii
    $s11 = "function pDOYSiKiT(ksnpO,InIEx,vdpmb) {" fullword ascii
    $s12 = "function XfgC(AkTNA) {" fullword ascii
    $s13 = "return new ActiveXObject(IwMAwB);" fullword ascii
    $s14 = "function mLyf(zvxgm) {" fullword ascii
    $s15 = "function Nnqo(VyZGM) {" fullword ascii
    $s16 = "function xKxR(ecHUb,BrMjS,rrNCz) {" fullword ascii
    $s17 = "if (gyPBs > 200618-688){return true;} else {return false;}" fullword ascii
    $s18 = "return eF.ExpandEnvironmentStrings(qS);" fullword ascii
    $s19 = "if (((new Date())>0,7863018888)) {" fullword ascii
    $s20 = "function wRXhdiFn() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}