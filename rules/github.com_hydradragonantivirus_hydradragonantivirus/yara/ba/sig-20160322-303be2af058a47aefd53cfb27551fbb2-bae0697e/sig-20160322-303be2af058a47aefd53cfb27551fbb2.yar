rule sig_20160322_303be2af058a47aefd53cfb27551fbb2 {
  meta:
    description = "datamaliciousorder - file 20160322_303be2af058a47aefd53cfb27551fbb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d381e230fa4cb443a355d8c85a99665771680074814b422caee98a2cd99e4eda"

  strings:
    $s1  = "return WScript.CreateObject(FfAcp);" fullword ascii
    $s2  = "return IrcCx.status;" fullword ascii
    $s3  = "function nhzN(IrcCx) {" fullword ascii
    $s4  = "var Ru = true  , XUTQ = rnA[7] + rnA[9] + rnA[11];" fullword ascii
    $s5  = "return szqPmGB[0] + szqPmGB[2] + szqPmGB[4] + \".F\" + szqPmGB[7] + szqPmGB[9] + szqPmGB[12] + szqPmGB[14];" fullword ascii
    $s6  = "var szqPmGB = XDPnl(ClJATqCmvq+\" \"+\"System qI sodUX Obj nbGDUf ect DufsjAR fCVVT\", \" \");" fullword ascii
    $s7  = "var rnA = (\"2.XMLHTTP LvfRAGn HNQsc XML ream St YrhpAdyH AD VIzTqbI O xtgf D\").split(\" \");" fullword ascii
    $s8  = "RLjq.open(KLuRH,JQVOR,false);" fullword ascii
    $s9  = "function qmXu(FfAcp) {" fullword ascii
    $s10 = "function puKf(mGbNE) {" fullword ascii
    $s11 = "if (oHylT > 159261-149){return true;} else {return false;}" fullword ascii
    $s12 = "function kyvY(RRHMF,JQVOR,KLuRH) {" fullword ascii
    $s13 = "return bRkC.ExpandEnvironmentStrings(cRCSg);" fullword ascii
    $s14 = "function gxzEv(ZsLSxY) {" fullword ascii
    $s15 = "wpu = f; break; " fullword ascii
    $s16 = "return OJM.split(adiwE);" fullword ascii
    $s17 = "function eckLzHpd(PGjy) {" fullword ascii
    $s18 = "function aYNe(ssREt) {" fullword ascii
    $s19 = "function XDPnl(OJM,adiwE) {" fullword ascii
    $s20 = "return AukO[AXZxPu[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}