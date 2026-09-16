rule sig_20160322_4c77b904c5e9de3ef0627bee33cbe347 {
  meta:
    description = "datamaliciousorder - file 20160322_4c77b904c5e9de3ef0627bee33cbe347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fb61be9544b50426432de873375100af332dce328e547891a44fe541fc4c4c5"

  strings:
    $s1  = "return WScript.CreateObject(PAawz);" fullword ascii
    $s2  = "return uafscGG[0] + uafscGG[2] + uafscGG[4] + \".F\" + uafscGG[7] + uafscGG[9] + uafscGG[12] + uafscGG[14];" fullword ascii
    $s3  = "var yK = true  , bXhf = OZn[7] + OZn[9] + OZn[11];" fullword ascii
    $s4  = "RgBYU.open(kqGnQ,gMGvD,false);" fullword ascii
    $s5  = "var uafscGG = YBzKi(VcLVRTKGIR+\" \"+\"System ap UHtVJ Obj UmXRSh ect DomkVii IXfNM\", \" \");" fullword ascii
    $s6  = "var OZn = (\"2.XMLHTTP WTHwrGY fXSag XML ream St SrSlfBFl AD GjmnUhv O OgqR D\").split(\" \");" fullword ascii
    $s7  = "function aIFW(iuaxa) {" fullword ascii
    $s8  = "function OETIDKg(OyUV,ZdhKZ) {" fullword ascii
    $s9  = "if (r >= iuaxa.length) {break;}" fullword ascii
    $s10 = "function eZZxvPsy(hGGO) {" fullword ascii
    $s11 = "function QYDl(RgBYU,gMGvD,kqGnQ) {" fullword ascii
    $s12 = "function crey(kulsT,GYjXu) {" fullword ascii
    $s13 = "function aAer(rNSOO) {" fullword ascii
    $s14 = "function uqaMXWjh(PCR) {" fullword ascii
    $s15 = "function QPUf(PAawz) {" fullword ascii
    $s16 = "iiH = a; break; " fullword ascii
    $s17 = "if (rNSOO == 954-754){return true;} else {return false;}" fullword ascii
    $s18 = "function wYKG(ZujIN) {" fullword ascii
    $s19 = "return PxXG[QVxmrh[0]];" fullword ascii
    $s20 = "if (torPg > 192676-551){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}