rule sig_20160309_9dcca9076e033dad0a2dd7a7ddec0dcd {
  meta:
    description = "datamaliciousorder - file 20160309_9dcca9076e033dad0a2dd7a7ddec0dcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35fd2ef58c0241de227a381693cac21bea46c90428e46e76b490f4007f6a37e6"

  strings:
    $s1  = "var zq = true  , NLiQ = fco[7] + fco[9] + fco[11];" fullword ascii
    $s2  = "return kBqtJWp[0] + kBqtJWp[2] + kBqtJWp[4] + \".F\" + kBqtJWp[7] + kBqtJWp[9] + kBqtJWp[12] + kBqtJWp[14];" fullword ascii
    $s3  = "var kBqtJWp = \"Sc XCfUdEk r xVaDggwlt ipting Yrjexzz mhc ile zqqPPsFBSPceqa System jh uGtlw Obj RlYNmJ ect mRWudpk\".split(\" " ascii
    $s4  = "ydkde.open(lokbS,vMbAf,false);" fullword ascii
    $s5  = "var fco = (\"2.XMLHTTP ilckFoB DORSP XML ream St YnakRfZf AD dWLMJgz O pZsH D\").split(\" \");" fullword ascii
    $s6  = "function ucKqbjB(GOWd) {" fullword ascii
    $s7  = "return FZqt.ExpandEnvironmentStrings(svojF);" fullword ascii
    $s8  = "function eaUgVCOw(pjPAn,kZRKYa) {" fullword ascii
    $s9  = "if(q>=S.length) {break;}" fullword ascii
    $s10 = "return GOWd.responseBody;" fullword ascii
    $s11 = "return XDsQoPD(FP,xuAhO[846-840]+xuAhO[294-287]+xuAhO[701-693]);" fullword ascii
    $s12 = "function FshXzcGG() {" fullword ascii
    $s13 = "return sqoUd.status;" fullword ascii
    $s14 = "function pCZo(oeDOM) {" fullword ascii
    $s15 = "if (lHUHo > 184071-298){return true;} else {return false;}" fullword ascii
    $s16 = "function tWyS(lHUHo) {" fullword ascii
    $s17 = "function BGWpKmZtU(hXyFT,oqWZs,wUktC,VWEV) {" fullword ascii
    $s18 = "function idlc(KNVSh) {" fullword ascii
    $s19 = "if (c >= MzGHg.length) {break;}" fullword ascii
    $s20 = "if (xImnj == 715-515){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}