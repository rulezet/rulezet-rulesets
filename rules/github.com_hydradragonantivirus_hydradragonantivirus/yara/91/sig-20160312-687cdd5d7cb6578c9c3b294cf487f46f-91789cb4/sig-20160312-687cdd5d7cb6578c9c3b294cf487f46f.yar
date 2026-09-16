rule sig_20160312_687cdd5d7cb6578c9c3b294cf487f46f {
  meta:
    description = "datamaliciousorder - file 20160312_687cdd5d7cb6578c9c3b294cf487f46f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7abcde0a991d6465072559199095168cf2c62dd55568669fd3be1586c2ff44bf"

  strings:
    $s1  = "var cDi = (\"2.XMLHTTP uZFZeyM comob XML ream St UoECWPVH AD hrMiIaD O AsIj D\").split(\" \");" fullword ascii
    $s2  = "return wklGnBw[0] + wklGnBw[2] + wklGnBw[4] + \".F\" + wklGnBw[7] + wklGnBw[9] + wklGnBw[12] + wklGnBw[14];" fullword ascii
    $s3  = "var nE = true  , SvIL = cDi[7] + cDi[9] + cDi[11];" fullword ascii
    $s4  = "var wklGnBw = \"Sc NJgARfO r hZRZhpaYO ipting bwIgoaD eYH ile hWGoIhCulpMlMv System xs JNCXk Obj vrZVzy ect bpCsRva\".split(\" " ascii
    $s5  = "mCULU.open(SPdqf,fSsqu,false);" fullword ascii
    $s6  = "if (C >= HCCnM.length) {break;}" fullword ascii
    $s7  = "return Ixfq.responseBody;" fullword ascii
    $s8  = "return oFNYy.status;" fullword ascii
    $s9  = "function DUnx(BcGTP) {" fullword ascii
    $s10 = "return new ActiveXObject(koiiNW);" fullword ascii
    $s11 = "function HrbVA(koiiNW) {" fullword ascii
    $s12 = "if (IYgPQ == 402-202){return true;} else {return false;}" fullword ascii
    $s13 = "function xBJM(IYgPQ) {" fullword ascii
    $s14 = "function XuQilxhsY() {" fullword ascii
    $s15 = "if(r>=a.length) {break;}" fullword ascii
    $s16 = "function aHeq(yqYBi,SaxlJ) {" fullword ascii
    $s17 = "function ovmG(IUOol) {" fullword ascii
    $s18 = "function Pfha(mCULU,fSsqu,SPdqf) {" fullword ascii
    $s19 = "function adci(NepYY) {" fullword ascii
    $s20 = "function JrZapLY(iFjw,WwqiY) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}