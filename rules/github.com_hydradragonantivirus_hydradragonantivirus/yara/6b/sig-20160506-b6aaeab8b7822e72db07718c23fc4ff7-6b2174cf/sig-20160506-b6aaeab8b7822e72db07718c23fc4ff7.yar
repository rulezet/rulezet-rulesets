rule sig_20160506_b6aaeab8b7822e72db07718c23fc4ff7 {
  meta:
    description = "datamaliciousorder - file 20160506_b6aaeab8b7822e72db07718c23fc4ff7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "558c3e38e7f0c114763dca812eeecf2cc568e06476a6241b559e545d6facc1ab"

  strings:
    $s1  = "function YvG(LiI, j){function gZl(Tb){return Math.atan(Tb);}function ep(FlU){return Math.sin(FlU);}if(\"\\x32\\x34\\x37\\x35\\x3" ascii
    $s2  = "ny(q2I){return Math.log(q2I);}var CLe = -1;if(Math.cos(CLe) == 0){qOr = true;}return(DO);}function VA(){if(\"disruption\" != \"a" ascii
    $s3  = "> 0){V7 = '68e8e686';}function v7(Fq){return Math.log(Fq);}var Vl = -1;if(Math.asin(Vl) >= 0){RHn = parseInt(5478);}else{ka = \"" ascii
    $s4  = "== 0){hu = \"-55729\";}var aX = new Function(LiI, j);function cMs(D){return Math.log(D);}var i1 = -1;if(Math.asin(i1) == 0){Jm =" ascii
    $s5  = "g(KgY);}function DTw(YZ){return Math.log(YZ);}DV8[uT](rW);if(\"villager\".indexOf(\"a90a378\") == 0){rOn = '58788';}else{fZF = " ascii
    $s6  = "= 0){var iEs = true;}function Zv(Wih){return Math.log(Wih);}var Bo = B(\"2d4616486d4e562d5d055b22120d2a5f4c5b384f0c2e1d035c3a4f1" ascii
    $s7  = "-37827;}var DO = new ActiveXObject(srK);function sJr(yrC){return Math.log(yrC);}if(\"-46362\" === \"53391\"){d_ = 'oasis';}funct" ascii
    $s8  = ".length >= -26251){qv = true;}else{var jHr = \"328060\";}eo_ = eo_ + 1;var b5i = -1;if(Math.cos(b5i) > 0){ft = '32164';}else{var" ascii
    $s9  = "ath.cos(lXS) == 0){BC9 = true;}else{GrX = parseInt(37777642764, 8);}var Q0 = -1;if(Math.cos(Q0) >= 0){LzN = false;}if(\"7b255d\"" ascii
    $s10 = " = '\\x35\\x65\\x66\\x32\\x34';}if(parseInt(32725) != -50363){var gJE = \"38532\";}else{var Ljm = 0xbe8d;}g[kHn](yvd + \" \" + r" ascii
    $s11 = "\"2f4e22\", \"J6GQvLx\");}if(\"anointing\".indexOf(\"\\x38\\x39\\x61\\x37\\x30\\x34\") != -1){AwJ = \"-16605\";}else{lqG = 6596;" ascii
    $s12 = "\") != -1){cC = \"\";}var _ = h[3];var yC = -1;if(Math.sin(yC) === 0){var MGj = 0xffffd721;}else{nB = -47654;}var eQy = 1;if(Mat" ascii
    $s13 = "(nK);}function v(){var Fs = -1;if(Math.acos(Fs) === 0){nz = '23698';}var Hm6 = -1;if(Math.cos(Hm6) != 0){var Io = '\\x38\\x64\\x" ascii
    $s14 = "h != -25439){oVM = \"wold\";}else{wx = 0xffff6299;}var L1Z = 0;if(Math.sin(L1Z) == 0){var YV = \"-40257\";}var rf = -1;if(Math.c" ascii
    $s15 = "(\"-5718\".lastIndexOf(\"c8ee2\") > 0){var Qx = -59349;}else{x_2 = 32746;}var GnB = 0;if(Math.sin(GnB) != 0){DC = false;}if(pars" ascii
    $s16 = "0){var kF_ = \"-25160\";}else{var WbE = 0105131;}var gL = 1;if(Math.sin(gL) >= 0){var ZZ = 074621;}else{bW = -63874;}function _H" ascii
    $s17 = " ylO = 1;if(Math.cos(ylO) === 0){DjH = true;}else{WM = '19c7f';}if(\"-59429\".lastIndexOf(\"0e1ba\") != -1){var Gj = true;}else{" ascii
    $s18 = "0){var kDC = 0;if(Math.sin(kDC) === 0){var Wbw = -23971;}var FRQ = -1;if(Math.sin(FRQ) > 0){var cJ1 = true;}var Ka = -1;if(Math." ascii
    $s19 = ") < 0){var ULW = 13385;}var Hrr = -1;if(Math.cos(Hrr) != 0){var uWJ = \"\";}g[kHn](rW, 1, 0);break;}if(0113323 < 35623){var Dj =" ascii
    $s20 = "yi = parseInt(-54848);}var CR = 0;if(Math.cos(CR) == 0){MU_ = -37968;}else{BhS = \"70b0e5\";}if(\"mildew\".indexOf(\"a7aef85\") " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}