rule sig_20160324_86dd58df58408486bf38f530c54475a3 {
  meta:
    description = "datamaliciousorder - file 20160324_86dd58df58408486bf38f530c54475a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38fd0101fb77743ee8a58795cac7501e63ca73cbb17df50e82bda7bf174f4ce1"

  strings:
    $s1  = "return WScript.CreateObject(WLYwT);" fullword ascii
    $s2  = "var Zh = true  , QkJl = OhQ[7] + OhQ[9] + OhQ[11];" fullword ascii
    $s3  = "return EzApPnT[0] + EzApPnT[2] + EzApPnT[4] + \".F\" + EzApPnT[7] + EzApPnT[9] + EzApPnT[12] + EzApPnT[14];" fullword ascii
    $s4  = "JgQh.open(wRKkc,xNxyS,false);" fullword ascii
    $s5  = "var OhQ = (\"2.XMLHTTP HevRzWO rRNnM XML ream St CljflBZW AD aahGkNL O UhJT D\").split(\" \");" fullword ascii
    $s6  = "var EzApPnT = hJJng(OmMXvCEywp+\" \"+\"System CQ vXsBN Obj qZhiYE ect jEQnFXx azYPV\", \" \");" fullword ascii
    $s7  = "return YslkZ;" fullword ascii
    $s8  = "function kmDC(shuGf) {" fullword ascii
    $s9  = "function jTvJN(NRWRvGoK,YOag) {" fullword ascii
    $s10 = "if (owxFc > 162927-576){return true;} else {return false;}" fullword ascii
    $s11 = "return XtYfG.status;" fullword ascii
    $s12 = "return hmXnUT/*G8n8MgwYmb1V1Y88oRxX1b3r1*/.position=514-514;" fullword ascii
    $s13 = "function HLVJ(XtYfG) {" fullword ascii
    $s14 = "function iTdBifKo(TBzE) {" fullword ascii
    $s15 = "return new ActiveXObject(LJtD);" fullword ascii
    $s16 = "function cxPHqAvQ(qUO) {" fullword ascii
    $s17 = "function Yjbe(kTNqS,zPOjD) {" fullword ascii
    $s18 = "return pYPf.ExpandEnvironmentStrings(uEgCL);" fullword ascii
    $s19 = "function aTfu(WBnvF) {" fullword ascii
    $s20 = "var vHCzOOf = \"QMNezk*rDw*pt.S\"+\"hell*hEwpdge*Scri*\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}