rule sig_20160311_5837ff74f0fae3e5e883a6fdc084927a {
  meta:
    description = "datamaliciousorder - file 20160311_5837ff74f0fae3e5e883a6fdc084927a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0059c66e16e511aea1f89504cd12249a3b8194796e1d41eea523aa6584997d5"

  strings:
    $s1  = "return hLFDavi[0] + hLFDavi[2] + hLFDavi[4] + \".F\" + hLFDavi[7] + hLFDavi[9] + hLFDavi[12] + hLFDavi[14];" fullword ascii
    $s2  = "var gx = true  , DQsp = PZv[7] + PZv[9] + PZv[11];" fullword ascii
    $s3  = "var hLFDavi = \"Sc glDmuNM r jzcoiktzs ipting FwjQgwG IrD ile gONarylLJMatXC System rN ZMzQf Obj eeFSXT ect zNoqcUj\".split(\" " ascii
    $s4  = "lRzfR.open(OhQgN,LbcWK,false);" fullword ascii
    $s5  = "var PZv = (\"2.XMLHTTP nXXlyuK SJcKy XML ream St EyPuUYAt AD nizxTgi O YyQC D\").split(\" \");" fullword ascii
    $s6  = "return TeAM.ExpandEnvironmentStrings(brQSV);" fullword ascii
    $s7  = "function xFvzlch(TeAM,brQSV) {" fullword ascii
    $s8  = "if (qAYQj > 122292-591){return true;} else {return false;}" fullword ascii
    $s9  = "function xVXP(qAYQj) {" fullword ascii
    $s10 = "if (xLinN == 361-161){return true;} else {return false;}" fullword ascii
    $s11 = "function QfGZwPaSc(nTeFahEEuGT) {" fullword ascii
    $s12 = "function CkiK(ArdMs,uIfjN) {" fullword ascii
    $s13 = "return RIiz.responseBody;" fullword ascii
    $s14 = "function bNDt(rrXTz) {" fullword ascii
    $s15 = "return xFvzlch(mf,CxKnL[376-370]+CxKnL[1005-998]+CxKnL[501-493]);" fullword ascii
    $s16 = "function vigS(LOvKh,BIHuW) {" fullword ascii
    $s17 = "function CZor(JSbbo) {" fullword ascii
    $s18 = "if (h >= McsXH.length) {break;}" fullword ascii
    $s19 = "return ggL.size;" fullword ascii
    $s20 = "function eqwK(lRzfR,LbcWK,OhQgN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}