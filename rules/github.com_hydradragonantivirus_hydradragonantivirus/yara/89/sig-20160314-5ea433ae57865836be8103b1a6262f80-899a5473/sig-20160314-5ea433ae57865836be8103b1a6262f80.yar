rule sig_20160314_5ea433ae57865836be8103b1a6262f80 {
  meta:
    description = "datamaliciousorder - file 20160314_5ea433ae57865836be8103b1a6262f80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c619a2673f0b9cf7fb7fccece76fdc19fa0ab0482fb6401c9c89670f8ac6f0c"

  strings:
    $s1  = "var Fg = true  , oWpW = Qay[7] + Qay[9] + Qay[11];" fullword ascii
    $s2  = "return nKccpkd[0] + nKccpkd[2] + nKccpkd[4] + \".F\" + nKccpkd[7] + nKccpkd[9] + nKccpkd[12] + nKccpkd[14];" fullword ascii
    $s3  = "function NurF(OecIg,bINLY) {" fullword ascii
    $s4  = "var nKccpkd = GMIpr(\"Sc NgMVAKJ r XDRQyDXEG ipting mXkzLPI epT ile aSGauvZrxKyqDo System TT xLUUL Obj YTvPKn ect gYufgQk VpMri" ascii
    $s5  = "var nKccpkd = GMIpr(\"Sc NgMVAKJ r XDRQyDXEG ipting mXkzLPI epT ile aSGauvZrxKyqDo System TT xLUUL Obj YTvPKn ect gYufgQk VpMri" ascii
    $s6  = "jdvmc.open(nwQDY,DTDLa,false);" fullword ascii
    $s7  = "function HikM(jdvmc,DTDLa,nwQDY) {" fullword ascii
    $s8  = "return OOPEu.status;" fullword ascii
    $s9  = "nUO = r; break; " fullword ascii
    $s10 = "function aciN(bKHzT) {" fullword ascii
    $s11 = "if (rTKdy > 173643-181){return true;} else {return false;}" fullword ascii
    $s12 = "return FVrB.ExpandEnvironmentStrings(xahpV);" fullword ascii
    $s13 = "return new ActiveXObject(JRdXnd);" fullword ascii
    $s14 = "if (y >= CUWFK.length) {break;}" fullword ascii
    $s15 = "function zTjFNgCR() {" fullword ascii
    $s16 = "return ANwYOLr" fullword ascii
    $s17 = "function JYaO(rTKdy) {" fullword ascii
    $s18 = "function BwuC(jVyeV) {" fullword ascii
    $s19 = "function aQMwn(QhziFz) {" fullword ascii
    $s20 = "function lgBP(CUWFK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}