rule sig_20160310_d3ce6057e74c35210d76caf90b18f007 {
  meta:
    description = "datamaliciousorder - file 20160310_d3ce6057e74c35210d76caf90b18f007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da7530e376afea1228eb864fed65d61446bea13112a8e7efed498d0b11a95d66"

  strings:
    $s1  = "return dMYesif[0] + dMYesif[2] + dMYesif[4] + \".F\" + dMYesif[7] + dMYesif[9] + dMYesif[12] + dMYesif[14];" fullword ascii
    $s2  = "var tI = true  , oMGk = RWs[7] + RWs[9] + RWs[11];" fullword ascii
    $s3  = "var RWs = (\"2.XMLHTTP aSeulOY yWmVQ XML ream St dOxTlbMH AD VqtUznv O xTuT D\").split(\" \");" fullword ascii
    $s4  = "OZXCp.open(elAdf,cmpMw,false);" fullword ascii
    $s5  = "var dMYesif = \"Sc vzNQmiv r iqCoTZyOu ipting MyJXyqT HkP ile RftiOgICiuxVts System WL xxQWv Obj WTJnka ect alknXbE\".split(\" " ascii
    $s6  = "function yOxK(wzZVb,ZJgjC) {" fullword ascii
    $s7  = "if (FVFvI > 190860-404){return true;} else {return false;}" fullword ascii
    $s8  = "return NclEukG(dR,COaUX[626-620]+COaUX[469-462]+COaUX[366-358]);" fullword ascii
    $s9  = "function WTGW(NfTdd) {" fullword ascii
    $s10 = "return PyAR.responseBody;" fullword ascii
    $s11 = "function uTXHWfuY(jDY) {" fullword ascii
    $s12 = "function BZYT(okSDv) {" fullword ascii
    $s13 = "HiE = W; break; " fullword ascii
    $s14 = "function mETi(ItxxE,TlWQS) {" fullword ascii
    $s15 = "function yXvlnzgLJ(lJtAI,OpOZy,dEVcL,RBBk) {" fullword ascii
    $s16 = "return jDY.size;" fullword ascii
    $s17 = "if (Q >= DTJOp.length) {break;}" fullword ascii
    $s18 = "return pBmFgHv" fullword ascii
    $s19 = "function cbtLjAfq() {" fullword ascii
    $s20 = "function PtWRI(irheMq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}