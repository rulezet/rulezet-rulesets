rule sig_20160506_790396fdaa4f06ff2ab9a7557df76403 {
  meta:
    description = "datamaliciousorder - file 20160506_790396fdaa4f06ff2ab9a7557df76403.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b9ecd0ee3d4c50407141824418883b5fa51591591a2b2baa3cd87df70e892d9"

  strings:
    $s1  = "function x(){if(\"1739\".length != parseInt(37777760432, 8)){var HNa = parseInt(-63838);}else{var DrI = \"occupancy\";}if(\"-211" ascii
    $s2  = ") >= 0){xY = -4385;}function TC(vb){return Math.log(vb);}var a4 = 1;if(Math.acos(a4) != 0){var TF = '\\x38\\x34\\x61\\x64';}else" ascii
    $s3  = "ar rR = '-44392';}function mb(Qe){return Math.log(Qe);}function ii_(Fi){return Math.tan(Fi);}if(\"156\" == \"53302\"){JPA = -206" ascii
    $s4  = ";}var YH = 1;if(Math.acos(YH) === 0){var ae1 = \"-29409\";}else{var WYS = 0x8800;}function JbT(gx){return Math.log(gx);}if(Q == " ascii
    $s5  = "0){var nh = \"\";}else{hk = \"\";}var H = sDC + \"\\\\\" + TZ + \".\" + rM;var rr = -1;if(Math.sin(rr) > 0){var DW = \"charity\"" ascii
    $s6  = "Math.cos(kMx) >= 0){e5 = 0xe22b;}else{var vo = false;}if(parseInt(-31487) != -22115){pBg = false;}else{vuq = '\\x35\\x35\\x33\\x" ascii
    $s7  = "\\x63\\x61\\x30\\x32\"){yy = false;}else{zT = 0xffff1e24;}var JF = -1;if(Math.cos(JF) > 0){bKS = '36236';}else{d2k = false;}if(p" ascii
    $s8  = "th.sin(NC) >= 0){CI = \"\";}function S7(NkJ){return Math.cos(NkJ);}if(\"34458\".length == -6100){ls = true;}return(J);}wa();" fullword ascii
    $s9  = "\";}var nc = \"gpl\";if(nc === \"\\x35\\x39\\x62\\x39\\x30\"){var Ueg = true;}var vL4 = -1;if(Math.sin(vL4) == 0){var k8F = fals" ascii
    $s10 = "\");}if(\"conviction\".lastIndexOf(\"46d06\") == 0){var D0 = true;}else{GsH = true;}var lKl = -1;if(Math.cos(lKl) > 0){var eMV =" ascii
    $s11 = " 30494){var Uk = 037777760245;}else{oP = -19800;}function hA(zJ){return Math.ceil(zJ);}var k9q = 1;if(Math.cos(k9q) === 0){var n" ascii
    $s12 = "ength < 0xffff5068){jP = 0x4b85;}var NZv = -1;if(Math.cos(NZv) === 0){var TtT = \"\";}else{var rTB = -31090;}var w5 = 1;if(Math." ascii
    $s13 = "arseInt(16633, 8);}var uAm = -1;if(Math.cos(uAm) == 0){var ker = true;}var pc = Pf9(j2);var io = 1;if(Math.asin(io) === 0){var p" ascii
    $s14 = "< 0x51f9){var ajr = \"felony\";}if(\"10543\".length != -46068){Qi = true;}else{var Fq = \"\\x39\\x39\\x30\\x64\";}var a8m = 1;if" ascii
    $s15 = "g = pc[qe];function Oo(uLM){return Math.abs(uLM);}if(\"d235\".length != parseInt(-31749)){_UV = -42157;}else{zX9 = \"\";}if(\"38" ascii
    $s16 = " = 'heavy';}else{var Vd = true;}var Afn = -1;if(Math.sin(Afn) === 0){QVl = 11524;}var ssh = -1;if(Math.asin(ssh) === 0){var Uwn " ascii
    $s17 = "f(Math.sin(Saj) > 0){var dVV = -8870;}else{var A8k = \"bf6ee1\";}if(0xffff6b4f <= 037777653272){sv = \"thailand\";}var k = gr(\"" ascii
    $s18 = "}if(\"\".indexOf(\"\\x62\\x31\\x62\\x61\\x61\\x34\\x30\\x33\") != -1){Aum = 0112435;}else{ScH = \"\";}var XQu = -1;if(Math.cos(X" ascii
    $s19 = "3\\x61\") != -1){p = '';}else{var el = false;}var ZU = 0;if(Math.sin(ZU) === 0){var OpO = -40053;}else{var zPl = \"-48295\";}if(" ascii
    $s20 = " \"FRAkjcI\");var SL = 1;if(Math.cos(SL) != 0){var Zx = -2371;}else{fyA = 0x585c;}if(parseInt(-21037) != -35847){var JX4 = '\\x3" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}