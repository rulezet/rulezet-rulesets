rule sig_20160507_78f1633ea07dc90f078bd4a556b5afd7 {
  meta:
    description = "datamaliciousorder - file 20160507_78f1633ea07dc90f078bd4a556b5afd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81123be6560d8d14d40929f4439e7dbc808354059e4794dbd691ecb7a1b09a63"

  strings:
    $s1  = "function K(W, R){if(\"58743\" != \"\\x64\\x39\\x39\\x37\\x32\"){I = true;}if(\"retorts\".indexOf(\"49925\") != -1){var dxO = 017" ascii
    $s2  = "ion Z0(am){return Math.log(am);}var _h = -1;if(Math.acos(_h) >= 0){var Aiw = \"-12832\";}else{J5O = \"-27189\";}var e = sSr[VO];" ascii
    $s3  = "tion d2(oA){return Math.log(oA);}if(\"\".lastIndexOf(\"-61919\") > 0){var P8p = true;}if(\"36874\".length > -36025){ABj = \"\";}" ascii
    $s4  = "r Sf = \"\";}function Me(heO){return Math.log(heO);}var cDg = 1;if(Math.asin(cDg) >= 0){ks = 0xffff7a22;}else{var KE = false;}if" ascii
    $s5  = "= 0xab40;}else{var vg = false;}if(\"62499\" == \"uproarious\"){var xM = false;}function A7(Fac){return Math.log(Fac);}if(\"\".in" ascii
    $s6  = "Math.acos(aY) > 0){deL = true;}var uWZ = sSr[AGM].substr(0, 2);if(\"circumlocution\".lastIndexOf(\"debatable\") != -1){var VS = " ascii
    $s7  = "if(Math.cos(SGK) != 0){eep = '1a1d4f';}if(0xffff341e == 01006){de = '3761';}else{var Zq = -31957;}eA = eA + 1;if(\"48940\" == \"" ascii
    $s8  = "k;}function WM(_Vq){return Math.exp(_Vq);}var CgL = -1;if(Math.acos(CgL) === 0){var Oyo = 0xfc92;}function uhw(N0b){return Math." ascii
    $s9  = " 0;if(Math.sin(AOf) >= 0){Fq = 0xffff255d;}else{var tIH = false;}return ERr;}function N2(ERr, lkB){if(0103421 != -11632){var YQ " ascii
    $s10 = "}if(\"-16115\" === \"46728\"){var DW = -57031;}else{ee = -6756;}var bs = -1;if(Math.cos(bs) >= 0){Ew6 = 0xffff7fa9;}Alu += Strin" ascii
    $s11 = "\"\") != -1){wLt = \"52246\";}var ZA = -1;if(Math.asin(ZA) >= 0){UB = false;}if(\"comprehensive\".lastIndexOf(\"45139\") != -1){" ascii
    $s12 = " >= 0){usp = '-3466';}var ar1 = -1;if(Math.cos(ar1) == 0){Xk = \"-33178\";}else{var gDg = 'incest';}if(-35530 === 037777633223){" ascii
    $s13 = "og(Hx);}function PdC(Cg){return Math.acos(Cg);}var DQ = -1;if(Math.acos(DQ) > 0){var ju = \"configuration\";}if(\"-57677\".index" ascii
    $s14 = "62';}var qM = -1;if(Math.sin(qM) > 0){lv = 34606;}else{nU = '\\x31\\x31\\x61\\x35\\x62';}if(\"-22595\".length <= -18118){var IOk" ascii
    $s15 = " zQX(AE){var En_ = 0;if(Math.acos(En_) != 0){var uG = parseInt(32929);}else{nQ0 = parseInt(115461, 8);}var dO = -1;if(Math.cos(d" ascii
    $s16 = "th.asin(_e) === 0){yC = '0190fa';}else{var p7 = -59437;}var KhH = -1;if(Math.sin(KhH) != 0){eH0 = '';}var zU = -1;if(Math.cos(zU" ascii
    $s17 = "174;}else{var FU = '\\x35\\x33\\x38\\x63';}function mb(Qe){return Math.acos(Qe);}var d6C = -1;if(Math.cos(d6C) != 0){var sEf = f" ascii
    $s18 = "false;}sSr[icP]();var nVp = -1;if(Math.cos(nVp) != 0){LGg = parseInt(37777667176, 8);}else{BMv = \"\";}var PE = -1;if(Math.cos(P" ascii
    $s19 = ") == 0){Mc = \"4335\";}else{var wc = 'incl';}var sSr = zQX(z);var w7 = -1;if(Math.sin(w7) >= 0){var yVT = '';}if(\"crisis\".inde" ascii
    $s20 = "=== 0){WZ = -5706;}function I3(_fQ){return Math.abs(_fQ);}function tF(Rl){return Math.abs(Rl);}if(\"49995\".lastIndexOf(\"47273" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}