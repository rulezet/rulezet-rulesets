rule sig_20160323_36ecfde79adff63811dfd43c93cd0d3c {
  meta:
    description = "datamaliciousorder - file 20160323_36ecfde79adff63811dfd43c93cd0d3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9dd61ccaae92c67c78699c3ad8eb88c45b1a6624ec714aa56d18d2c69eb2005"

  strings:
    $s1  = "return WScript.CreateObject(aHCWu);" fullword ascii
    $s2  = "return WBropwT[0] + WBropwT[2] + WBropwT[4] + \".F\" + WBropwT[7] + WBropwT[9] + WBropwT[12] + WBropwT[14];" fullword ascii
    $s3  = "var PS = true  , ATaI = LCI[7] + LCI[9] + LCI[11];" fullword ascii
    $s4  = "var LCI = (\"2.XMLHTTP gfiNfiI PclMZ XML ream St viAsPldT AD OoajNOM O Jhiv D\").split(\" \");" fullword ascii
    $s5  = "var WBropwT = jrCyP(uPtyzFZGcs+\" \"+\"System NY Unfcd Obj QzpzBL ect jmHAySx VUdes\", \" \");" fullword ascii
    $s6  = "eWix.open(MghTh,QyTMZ,false);" fullword ascii
    $s7  = "if(K>=Y.length) {break;}" fullword ascii
    $s8  = "function zPLLR(gPDpZQ) {" fullword ascii
    $s9  = "function asMKpln(nFMN) {" fullword ascii
    $s10 = "function YccQ(kIgwh,tqcEc) {" fullword ascii
    $s11 = "return nFMN[gTmClq[0]];" fullword ascii
    $s12 = "return uGfezc/*W3gorScJ7CYvJboIBIfe9kp29*/.position=644-644;" fullword ascii
    $s13 = "return sRUPwtf(Ui,BAGqZ[487-481]+BAGqZ[635-628]+BAGqZ[672-664]);" fullword ascii
    $s14 = "function NYcFo(uGfezc) {" fullword ascii
    $s15 = "return new ActiveXObject(pwFb);" fullword ascii
    $s16 = "function sRUPwtf(KBCw,ehLaU) {" fullword ascii
    $s17 = "if (fpMta == 452-252){return true;} else {return false;}" fullword ascii
    $s18 = "return kOQ.size;" fullword ascii
    $s19 = "return LfnNl;" fullword ascii
    $s20 = "function jrCyP(Dzn,lsSta) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}