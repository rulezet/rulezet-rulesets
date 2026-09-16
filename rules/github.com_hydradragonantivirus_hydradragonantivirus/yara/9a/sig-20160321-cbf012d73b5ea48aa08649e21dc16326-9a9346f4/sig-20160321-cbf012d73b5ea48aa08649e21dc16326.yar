rule sig_20160321_cbf012d73b5ea48aa08649e21dc16326 {
  meta:
    description = "datamaliciousorder - file 20160321_cbf012d73b5ea48aa08649e21dc16326.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6440b9256e932007f97f43f00bb2cccef42eb0be0894f963f35ac2978c4ac6aa"

  strings:
    $s1  = "return WScript.CreateObject(DzcNk);" fullword ascii
    $s2  = "return eitLbVh[0] + eitLbVh[2] + eitLbVh[4] + \".F\" + eitLbVh[7] + eitLbVh[9] + eitLbVh[12] + eitLbVh[14];" fullword ascii
    $s3  = "var zu = true  , mStb = BoO[7] + BoO[9] + BoO[11];" fullword ascii
    $s4  = "var BoO = (\"2.XMLHTTP hCkbCwA CMqLY XML ream St IjKBwHAo AD NGBOrwn O SlIb D\").split(\" \");" fullword ascii
    $s5  = "OQuni.open(plYcK,UcHTr,false);" fullword ascii
    $s6  = "var eitLbVh = LINwR(syOIXaAbJQ+\" \"+\"System VI ftrOk Obj djGWEG ect ZDdUVzQ PRSQi\", \" \");" fullword ascii
    $s7  = "function AJYp(tuCZf,HUodw) {" fullword ascii
    $s8  = "function aqbgjBf(ufEF) {" fullword ascii
    $s9  = "return hKHYkv.position=214-214;" fullword ascii
    $s10 = "function QxKBENYr(clqn) {" fullword ascii
    $s11 = "return NKkCf;" fullword ascii
    $s12 = "if (Z >= CHFKL.length) {break;}" fullword ascii
    $s13 = "if (CgcNz == 391-191){return true;} else {return false;}" fullword ascii
    $s14 = "return BPgka.status;" fullword ascii
    $s15 = "function iPZe(imEMr) {" fullword ascii
    $s16 = "function wdmznHRoF(kAcZg) {" fullword ascii
    $s17 = "function XsKG(sWWsp,HePGG) {" fullword ascii
    $s18 = "return YbQ.split(owEwd);" fullword ascii
    $s19 = "function aVFT(CgcNz) {" fullword ascii
    $s20 = "function bnfT(DzcNk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}