rule sig_20160505_73537e55b8b6b20ed9cc3ae4a2f360f5 {
  meta:
    description = "datamaliciousorder - file 20160505_73537e55b8b6b20ed9cc3ae4a2f360f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75a60e941e34fa6d80e9e810d7f267d9e7bb74b1367bccfb04acbfe6accd9128"

  strings:
    $x1  = "function lp(gQ){var Ed = -1;if(Math.sin(Ed) > 0){IK = 0xe1d;}else{var fQ = false;}var Z = 0;if(Math.sin(Z) > 0){var Q = \"\\x32" ascii
    $s2  = " = -1;if(Math.asin(gCd) == 0){pem = true;}var gu = 0;if(Math.cos(gu) >= 0){Q0 = true;}if(\"fake\".indexOf(\"-23144\") > 0){EY2 =" ascii
    $s3  = "\\x32\\x38';}var Nm = 1;if(Math.sin(Nm) == 0){bco = \"\";}else{var K1 = '-65423';}var x = JG5(\"1c17101f00\", \"key\");var Bc = " ascii
    $s4  = "-33530\";}catch(dCi){Wqz = 0xffff3ac4;}var jKu = JG5(\"1800170f\", \"key\");function Nd(jAu){return Math.log(jAu);}if(\"e634932b" ascii
    $s5  = "h.asin(qH) != 0){IW = false;}var j = JG5(\"19000a1b0a1718000d0e1d0d\", \"key\");var nFb = -1;if(Math.cos(nFb) != 0){KD = \"\\x62" ascii
    $s6  = " \"key\");var DvC = 0;if(Math.acos(DvC) == 0){eL = true;}var InU = -1;if(Math.sin(InU) === 0){var nFM = \"55086\";}else{var WI =" ascii
    $s7  = "61186\";}else{Zv = parseInt(11111111111111110111011000011111, 2);}var Mp = 1;if(Math.cos(Mp) != 0){kwW = \"41633\";}else{O = -56" ascii
    $s8  = "ndexOf(\"d6a31d\") == -1){_UV = parseInt(11111111111111110010101100101100, 2);}else{zX9 = \"-56453\";}var W9t = -1;if(Math.sin(W" ascii
    $s9  = "39\\x37\\x65\";}var cSW = 1;if(Math.sin(cSW) >= 0){mkl = \"bf75\";}function mTJ(ogl){return Math.tan(ogl);}if(\"26234\".indexOf(" ascii
    $s10 = "se{o = true;}return(L);}function Iu(){if(parseInt(-48880) <= -15990){var NF = \"7634e\";}var cn = 1;if(Math.sin(cn) >= 0){d2g = " ascii
    $s11 = " 0;if(Math.cos(eK) > 0){var xFd = -11185;}else{eR9 = parseInt(37317);}if(0125305 <= parseInt(11001000001111, 2)){var BY = \"2861" ascii
    $s12 = "=== 0){var lG = -9084;}if(0x4ea0 <= 63616){vmZ = false;}else{mR = '28011';}aX[iD]();var nrs = 0;if(Math.cos(nrs) >= 0){var NS = " ascii
    $s13 = "In) >= 0){var ht = true;}var mk4 = -1;if(Math.sin(mk4) > 0){qUk = true;}else{var YW6 = '-22821';}if(parseInt(110110000001101, 2)" ascii
    $s14 = "x](VGh);var XA = -1;if(Math.cos(XA) >= 0){l8H = true;}else{var dAD = \"18464425\";}var IFz = -1;if(Math.acos(IFz) === 0){var bbE" ascii
    $s15 = "function lp(gQ){var Ed = -1;if(Math.sin(Ed) > 0){IK = 0xe1d;}else{var fQ = false;}var Z = 0;if(Math.sin(Z) > 0){var Q = \"\\x32" ascii
    $s16 = "8f21\";}var QG = -1;if(Math.sin(QG) > 0){var Uk = 0xffffc2f0;}else{In = 037777763220;}var f6x = JG5(\"1c161a190c091f4b0a03001507" ascii
    $s17 = "var M1 = true;}var pn = \"\";var vJ_ = -1;if(Math.sin(vJ_) == 0){var kfH = \"-32226\";}else{var U = parseInt(23448);}if(0xffff0c" ascii
    $s18 = ".acos(KKY) === 0){Jl = false;}var NG = 1;if(Math.sin(NG) >= 0){wY1 = \"2fe07100\";}var aX = zgS(lW1);var Xr = -1;if(Math.acos(Xr" ascii
    $s19 = "\";var Yn = \"ar\";if(KU === Yn){var bDT = '';}if(-14822 != parseInt(-20001)){xcD = false;}var gI = -1;if(Math.cos(gI) != 0){var" ascii
    $s20 = "-47198';}else{KGN = \"gross\";}var byc = -1;if(Math.cos(byc) === 0){var tWq = \"-34952\";}else{var U9Q = 0x3f58;}function tT(a4o" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}