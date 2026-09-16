rule sig_20160505_d5b4921a4a95ceec15e5a76148db779e {
  meta:
    description = "datamaliciousorder - file 20160505_d5b4921a4a95ceec15e5a76148db779e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b2485a67945bc572d91f4eee6fd5e8a3fa8dd421f17821051a275a1d2b4bceb"

  strings:
    $s1  = "function h2R(y, g){var h = -1;if(Math.cos(h) == 0){V8x = \"-8342\";}else{var Zk = '16521';}if(\"cc\".indexOf(\"reproductive\") >" ascii
    $s2  = " = h2R(\"19000a1b0a1718000d0e1d0d\", \"key\");var ERr = 0;if(Math.asin(ERr) != 0){var NS = -43678;}function CZ(wa){return Math.l" ascii
    $s3  = "0\\x39\\x33\\x37\\x35\\x39\";}var aku = 0;if(Math.asin(aku) != 0){var dS = true;}else{fZ = \"-42273\";}function FH(w8){return Ma" ascii
    $s4  = "if(uQn != eKR){IOX = true;}function Nvr(gt){return Math.log(gt);}if(\"\".length <= 0xffff46f3){var pu = true;}else{ML = true;}if" ascii
    $s5  = "RN = false;}if(\"59334\".indexOf(\"\") > 0){ZL = false;}else{var Mve = 'admit';}function EXG(jkn){return Math.log(jkn);}function" ascii
    $s6  = " \"63787\";}var RR = -1;if(Math.sin(RR) == 0){XM = true;}var b = h2R(\"1c17101f00\", \"key\");function gZl(Tb){return Math.abs(T" ascii
    $s7  = "041d064b1c1300055b19481755\", \"key\");var IK = -1;if(Math.cos(IK) >= 0){pJa = '1080';}else{var joR = parseInt(145630, 8);}var M" ascii
    $s8  = "2R(\"0e1d1c\", \"key\");}var hj = -1;if(Math.sin(hj) === 0){wmD = false;}else{np = '\\x62\\x32\\x62\\x65\\x35\\x35\\x65\\x30';}i" ascii
    $s9  = "2\\x66\\x37\\x36';}var B = h2R(\"1c161a190c091f4b0a03001507\", \"key\");var hi = -1;if(Math.cos(hi) == 0){var hT = true;}if(\"-4" ascii
    $s10 = " true;}var uKy = -1;if(Math.sin(uKy) == 0){var Du = 'bcbbe077';}var aT = h2R(\"0809161800\", \"key\");if(parseInt(37777665472, 8" ascii
    $s11 = "ath.sin(hQ) === 0){var oPL = parseInt(11111111111111110001111011011111, 2);}else{var _Vq = \"\\x31\\x64\\x39\\x33\\x36\\x64\";}i" ascii
    $s12 = "01111010111010, 2);}function Hld(vsn){return Math.exp(vsn);}Llt[rNj](eGz);function qFQ(Zg){return Math.atan(Zg);}var FBS = -1;if" ascii
    $s13 = "0175143;}else{var CWk = false;}if(EFl[Zyj] == 1){var zLi = 1;if(Math.sin(zLi) >= 0){var BY = \"9143\";}var lIh = -1;if(Math.acos" ascii
    $s14 = "3195);}var tQF = -1;if(Math.cos(tQF) > 0){var J_C = parseInt(38075);}for(T = 0; T < Ke.length; T++){try{function VsN(vPS){return" ascii
    $s15 = "(Math.acos(Z8T) != 0){var GRr = -57025;}var FdF = new Function(XI, e);var iZz = 0;if(Math.cos(iZz) > 0){var nHw = -26738;}else{v" ascii
    $s16 = " 2);}else{var gh = false;}var dTp = -1;if(Math.cos(dTp) == 0){var vs = \"26569\";}else{mC2 = \"36322\";}if(\"42197\".lastIndexOf" ascii
    $s17 = "key\");if(\"\\x66\\x35\\x32\\x30\\x66\\x36\".indexOf(\"\\x33\\x61\\x36\\x39\\x64\\x64\") == -1){var bDT = 'allowing';}else{var Q" ascii
    $s18 = "function h2R(y, g){var h = -1;if(Math.cos(h) == 0){V8x = \"-8342\";}else{var Zk = '16521';}if(\"cc\".indexOf(\"reproductive\") >" ascii
    $s19 = "(Math.cos(FBS) >= 0){CY = \"\";}else{var OC = 'e58a905';}if(\"a389e3\".indexOf(\"8158\") == -1){RF = false;}if(30744 == 0157716)" ascii
    $s20 = "E = 0xffffe77b;}function kI(kE){return Math.exp(kE);}Llt[b](Idx);var cst = -1;if(Math.sin(cst) >= 0){Bbm = 0xffffb5ac;}function " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}