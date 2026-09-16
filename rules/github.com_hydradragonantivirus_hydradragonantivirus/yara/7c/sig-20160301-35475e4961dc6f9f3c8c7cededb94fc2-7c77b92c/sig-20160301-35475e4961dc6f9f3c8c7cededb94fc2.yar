rule sig_20160301_35475e4961dc6f9f3c8c7cededb94fc2 {
  meta:
    description = "datamaliciousorder - file 20160301_35475e4961dc6f9f3c8c7cededb94fc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9aeaf21724a7d05143542d2764ef4d7e21132a27052c8ed906e318ec77d21f9c"

  strings:
    $s1  = "var Ox = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(QmxNs);" fullword ascii
    $s3  = "var kcJ = (ZKq + \"TTP\" + \" GAvvsof vRkXj XML ream St oEzqMBbj AD GxfFKiB OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + RncIkUS + \".F\" + KRkYdWoKEm + RIPxe + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var aR = true  , FgFZ = kcJ[7] + \"\" + kcJ[9];" fullword ascii
    $s6  = "xfZgC.open(TaUjF,LXqEj,false);" fullword ascii
    $s7  = "return FF.ExpandEnvironmentStrings(Ox);" fullword ascii
    $s8  = "function LRxb(AUFjM,jbohl) {" fullword ascii
    $s9  = "function MkFBw(KxCHzl) {" fullword ascii
    $s10 = "function xBGDPogIk(HgyXejiBEpk) {" fullword ascii
    $s11 = "function onoSYkPQ() {" fullword ascii
    $s12 = "return new ActiveXObject(KxCHzl);" fullword ascii
    $s13 = "function ckyr(zcjGn) {" fullword ascii
    $s14 = "function bmJF(soqdK,glBvi) {" fullword ascii
    $s15 = "function BsMOtqpig(pbdNk,iAPxV,YRDnl) {" fullword ascii
    $s16 = "if (BxIQy == 459-259){return true;} else {return false;}" fullword ascii
    $s17 = "return qifJc;" fullword ascii
    $s18 = "function fYVL(gGPDN) {" fullword ascii
    $s19 = "function MOOu(xfZgC,LXqEj,TaUjF) {" fullword ascii
    $s20 = "if (((new Date())>0,7558671888)) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}