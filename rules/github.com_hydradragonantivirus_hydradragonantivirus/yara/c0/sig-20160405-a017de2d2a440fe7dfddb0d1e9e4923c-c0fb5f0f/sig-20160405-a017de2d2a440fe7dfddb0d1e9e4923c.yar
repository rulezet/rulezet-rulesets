rule sig_20160405_a017de2d2a440fe7dfddb0d1e9e4923c {
  meta:
    description = "datamaliciousorder - file 20160405_a017de2d2a440fe7dfddb0d1e9e4923c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1020530efce8072659d7c1b881d15f8c5b185db1daaeeaf524fdd5fe9544f6f0"

  strings:
    $s1  = "return tSTSVUn[0] + tSTSVUn[2] + tSTSVUn[4] + \".F\" + tSTSVUn[7] + tSTSVUn[9] + tSTSVUn[12] + tSTSVUn[14];" fullword ascii
    $s2  = "var MJ = true  , qBAC = DlF[7] + DlF[9] + DlF[11];" fullword ascii
    $s3  = "var DlF = (\"2.XMLHTTP KJyGRae jSInv XML ream St FZRwmwXU AD TeTQHiv O puwR D\").split(\" \");" fullword ascii
    $s4  = "ueaW.open(xVAig,WvuzH,false);" fullword ascii
    $s5  = "return \"HUvFTwlyLLwWZn\";" fullword ascii
    $s6  = "function keph(AeNLH) {" fullword ascii
    $s7  = "return UIozCrB[0];" fullword ascii
    $s8  = "function sBBeK(wEq,uAVKi) {" fullword ascii
    $s9  = "return bkHeXjs;" fullword ascii
    $s10 = "function LNUhxJVCf(qAwSL) {" fullword ascii
    $s11 = "return wEq.split(uAVKi);" fullword ascii
    $s12 = "function yTgcyEXLo(obOaWNBTbbM) {" fullword ascii
    $s13 = "if (xhgkd == 936-736){return true;} else {return false;}" fullword ascii
    $s14 = "if(j>=p.length) {break;}" fullword ascii
    $s15 = "return zJmi;" fullword ascii
    $s16 = "return QLIlZ;" fullword ascii
    $s17 = "function uLWHX(SUrhBSiV,MjrU) {" fullword ascii
    $s18 = "IDG = j; break; " fullword ascii
    $s19 = "function wkdo(PtWSe,opCSn) {" fullword ascii
    $s20 = "function qHpYSwwx(iHq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}