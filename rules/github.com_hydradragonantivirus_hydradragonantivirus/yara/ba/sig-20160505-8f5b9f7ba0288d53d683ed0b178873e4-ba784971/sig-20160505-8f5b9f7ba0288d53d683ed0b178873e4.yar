rule sig_20160505_8f5b9f7ba0288d53d683ed0b178873e4 {
  meta:
    description = "datamaliciousorder - file 20160505_8f5b9f7ba0288d53d683ed0b178873e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "627a0999cbec26ec1a2edda877be313e7d556d951480df48bcde3961bd97927b"

  strings:
    $x1  = "function q(hD0, EV){if(\"\".length < parseInt(37777643743, 8)){v = true;}if(\"cfb44\".length < -25608){BQ = false;}var ics = -1;" ascii
    $s2  = "e;}else{var RMq = 'puss';}if(0xec70 == parseInt(-25541)){uj = '42287';}function En_(In){return Math.log(In);}var dO = 1;if(Math." ascii
    $s3  = "= false;}if(-55489 < parseInt(1010111101011, 2)){var nn = 0xffffea97;}else{Daq = 32591;}function JGD(dRD){return Math.log(dRD);}" ascii
    $s4  = "function BWr(jI){return Math.ceil(jI);}function gdj(pYP){return Math.log(pYP);}var s = rN(\"18060b02150d020b1e45031007000a12160d" ascii
    $s5  = "SpM) != 0){var SXV = 'revealed';}oI[KP](T + \" \" + f3 + \" \" + xQv, 1, 0);break;case 1:function uk(mP){return Math.log(mP);}va" ascii
    $s6  = "(zuP) >= 0){var BrF = -31484;}var L = rN(\"0c000d18151c080c1807031607011c19\", \"key\");function KVg(NIb){return Math.acos(NIb);" ascii
    $s7  = "r f3 = ogl + \"\\\\\" + O + \".\" + QZD;if(\"\".indexOf(\"\\x62\\x31\\x62\\x31\\x61\\x64\\x33\\x62\") == -1){var pAd = \"mahogan" ascii
    $s8  = "s(Rw) === 0){var rf = parseInt(28529);}function zPF(lf){return Math.tan(lf);}if(Z9y[P] == 200){var Xp = \"deliver\";if(Xp != \"p" ascii
    $s9  = "posted\"){var s0 = 0xffff9905;}if(\"\".length === 0xffff14cb){var f9 = false;}else{O_q = true;}var Wl = 1;if(Math.sin(Wl) > 0){O" ascii
    $s10 = "e;}var kC = -1;if(Math.sin(kC) != 0){var yg = \"\\x66\\x30\\x37\\x30\\x64\\x38\\x36\\x32\";}else{lv3 = \"\\x30\\x31\\x36\\x62\\x" ascii
    $s11 = "kjs = \"\";}else{var ilK = parseInt(37777657226, 8);}var _Q = -1;if(Math.cos(_Q) == 0){bVq = 0xffff9151;}var ogc = 0;if(Math.sin" ascii
    $s12 = "7611 === -30209){Q1q = false;}var lKa = 1;if(Math.cos(lKa) != 0){r_Y = \"\\x62\\x38\\x62\\x32\\x39\";}else{dyc = parseInt(101101" ascii
    $s13 = "{if(\"\\x66\\x35\\x39\\x63\\x64\\x65\" === \"\"){var zwp = '59537';}else{var Qj = false;}var hE = -1;if(Math.cos(hE) > 0){l6 = t" ascii
    $s14 = ");}if(\"59780\".lastIndexOf(\"ec82bd5\") != -1){var qf = '-10124';}var _0 = 1;if(Math.sin(_0) > 0){var nI = 'bulge';}else{yz = '" ascii
    $s15 = "h.asin(eRM) == 0){var mr = 'dennis';}var O = kbV();function Il(uu){return Math.sin(uu);}var mtG = -1;if(Math.acos(mtG) == 0){var" ascii
    $s16 = "ath.acos(ics) != 0){iS = true;}var iUd = new Function(hD0, EV);if(\"\\x38\\x34\\x62\\x64\\x63\\x31\".indexOf(\"\") == -1){var gx" ascii
    $s17 = "(37777762357, 8);}var Kl = -1;if(Math.cos(Kl) == 0){var kkk = true;}if(\"dce61ef\".indexOf(\"-53055\") < 0){var M1 = true;}else{" ascii
    $s18 = "= false;}var MKa = 0;var O2W = -1;if(Math.acos(O2W) != 0){Fh = 'entrails';}else{var Ftb = 46051;}var jqo = 0;if(Math.cos(jqo) !=" ascii
    $s19 = "c){return Math.abs(O1c);}var kY = -1;if(Math.acos(kY) === 0){ACx = false;}var aC3 = 1;if(Math.sin(aC3) == 0){var YO = \"19273\";" ascii
    $s20 = " = false;}var Jv = -1;if(Math.sin(Jv) == 0){uHY = '1806';}else{var avm = parseInt(1100000000011010, 2);}var FYw = rN(\"04151c05" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}