rule sig_20160505_6d75456c9ed1f3b4582fe397a5e819e5 {
  meta:
    description = "datamaliciousorder - file 20160505_6d75456c9ed1f3b4582fe397a5e819e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23b2aab212bf276fe91c1ec9a091f84b11306307da77583d557b4e3e33fd5942"

  strings:
    $x1  = "function Q(cd, kL8){var In = -1;if(Math.sin(In) === 0){var ICE = true;}else{var dQ = '\\x37\\x31\\x33\\x61\\x36';}if(\"\".length" ascii
    $s2  = "r bZ = -32562;}else{szV = parseInt(11111111111111111001001000011000, 2);}function XK(LzW){return Math.log(LzW);}var ISk = 1;if(M" ascii
    $s3  = "-1;if(Math.cos(BM) != 0){var gw = \"-60581\";}var HXj = xW(\"0e1d1c\", \"key\");}if(\"-2200\".lastIndexOf(\"12314\") == -1){DOQ " ascii
    $s4  = "ath.sin(ISk) == 0){FP = false;}else{var PJO = \"16fe58\";}var Bax = -1;if(Math.cos(Bax) != 0){var Vre = \"-51198\";}function tV(" ascii
    $s5  = "(\"0c000d18151c080c1807031607011c19\", \"key\");function icj(CRx){return Math.round(CRx);}var Vj = 0;if(Math.asin(Vj) === 0){mfE" ascii
    $s6  = "(-4569);}else{Ekn = \"29533\";}if(\"\".indexOf(\"vegas\") == -1){var fD = false;}var WM = Math.floor(Math.random() * 65536);if(" ascii
    $s7  = ">= 0){DGX = true;}else{var hX = 037777601073;}var KZ = 0;if(Math.cos(KZ) > 0){wmK = \"\";}if(Z3k[Bv_] == 200){var wop = -1;if(Ma" ascii
    $s8  = "f(\"purr\".indexOf(\"-29469\") == 0){var g_u = 'fea9c11c';}else{DCZ = \"planes\";}var E_ = xW(\"04151c05\", \"key\");var wn = -1" ascii
    $s9  = "011111111011, 2) === 0x724f){Qt = '14296';}else{kC_ = \"63228\";}T0 = T0 + 1;var hbz = 0;if(Math.cos(hbz) >= 0){var IQ = \"-2903" ascii
    $s10 = "(\"f9dce56d\".lastIndexOf(\"59247\") > 0){var j_ = true;}else{sji = false;}var GlY = -1;if(Math.cos(GlY) > 0){Fa = true;}var o3 " ascii
    $s11 = "ar RJ = -1;if(Math.acos(RJ) >= 0){var nhc = false;}else{var y4 = '';}var K = zQ[q].split(\"|\");var PSG = 0;if(Math.cos(PSG) > 0" ascii
    $s12 = "0e1d0d\", \"key\");var sJ = 0;if(Math.acos(sJ) >= 0){pBg = false;}if(\"teams\".indexOf(\"\\x39\\x32\\x33\\x35\\x30\\x64\\x65\") " ascii
    $s13 = " fu = -43251;}else{QsX = 0xfffff903;}var mh = xW(\"0a01160f075718110b0e0414\", \"key\");var gre = 0;if(Math.asin(gre) === 0){lH6" ascii
    $s14 = "false;}else{Hnc = '';}var aqy = -1;if(Math.sin(aqy) === 0){Ou = '50709';}if(\"-46079\" === \"pull\"){var XvW = '-46323';}else{HK" ascii
    $s15 = "return Math.ceil(DBs);}var Tc = -1;if(Math.asin(Tc) != 0){X8 = \"token\";}else{var eqX = 46356;}var fH = 1;if(Math.acos(fH) > 0)" ascii
    $s16 = "ngth >= -58637){lX = parseInt(1110110011111110, 2);}else{var CBb = false;}var Zl = 0;if(Math.cos(Zl) != 0){var wX = \"-7765\";}e" ascii
    $s17 = " = true;}var fNv = Z3k[wgM];var nVp = -1;if(Math.sin(nVp) === 0){var b8Z = \"\";}var Q1q = 1;if(Math.cos(Q1q) > 0){var Lgn = \"1" ascii
    $s18 = "curvature\";}var HXj = xW(\"0f0915\", \"key\");}else{var UBK = -1;if(Math.acos(UBK) >= 0){VfH = \"-46217\";}else{var KUE = '-201" ascii
    $s19 = "function Q(cd, kL8){var In = -1;if(Math.sin(In) === 0){var ICE = true;}else{var dQ = '\\x37\\x31\\x33\\x61\\x36';}if(\"\".length" ascii
    $s20 = "UJ) === 0){lnf = false;}function lc(LV){return Math.cos(LV);}var a = -1;if(Math.sin(a) == 0){var MuH = \"-23401\";}var _6 = new " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}