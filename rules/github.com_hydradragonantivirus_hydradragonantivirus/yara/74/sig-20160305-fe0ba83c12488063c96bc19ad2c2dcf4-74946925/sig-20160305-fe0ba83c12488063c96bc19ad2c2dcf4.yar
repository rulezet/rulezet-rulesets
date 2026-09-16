rule sig_20160305_fe0ba83c12488063c96bc19ad2c2dcf4 {
  meta:
    description = "datamaliciousorder - file 20160305_fe0ba83c12488063c96bc19ad2c2dcf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4d0806beb9ddd97c85d3c2dbf1fc46581ecf2502fd3ef3f9712c3aa378ded0b"

  strings:
    $s1  = "var smQyP = \"viASJg JLS pt.Shell WeyFzVk Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var keIerVS = \"Sc ADqyOic r ToXoYsKWw ipting bHiiemn BeE ile mWcofbJPOZaWWm System Ve zcOMc Obj CBhXjp ect HDzjwlo\".split(\" " ascii
    $s3  = "return keIerVS[0] + keIerVS[2] + keIerVS[4] + \".F\" + keIerVS[7] + keIerVS[9] + keIerVS[12] + keIerVS[14];" fullword ascii
    $s4  = "var yBD = (qlE + \"TTP\" + \" lfsPuWC QURNE XML ream St ibPKMKnx AD fxVBLlo OD\").split(\" \");" fullword ascii
    $s5  = "var kL = true  , NJWT = yBD[7] + \"\" + yBD[9];" fullword ascii
    $s6  = "GKzNI.open(LYjhD,wXqRP,false);" fullword ascii
    $s7  = "function unDP(ziBOc) {" fullword ascii
    $s8  = "function QtrB(vOVBQ,mGACD) {" fullword ascii
    $s9  = "function ONbX(GKzNI,wXqRP,LYjhD) {" fullword ascii
    $s10 = "function eszgQhI(Vsrt) {" fullword ascii
    $s11 = "if (tVyTQ > 184015-515){return true;} else {return false;}" fullword ascii
    $s12 = "function XWiFGMy(LszR) {" fullword ascii
    $s13 = "function PvLuTGAac(NjBhiUNYoVx) {" fullword ascii
    $s14 = "function tSVZ(tVyTQ) {" fullword ascii
    $s15 = "function nVlC(fnxbj) {" fullword ascii
    $s16 = "return fnxbj.status;" fullword ascii
    $s17 = "return LszR.responseBody;" fullword ascii
    $s18 = "return Ht.ExpandEnvironmentStrings(smQyP[6]);" fullword ascii
    $s19 = "function yMLJ(LsSGz) {" fullword ascii
    $s20 = "return xiMMeQs" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}