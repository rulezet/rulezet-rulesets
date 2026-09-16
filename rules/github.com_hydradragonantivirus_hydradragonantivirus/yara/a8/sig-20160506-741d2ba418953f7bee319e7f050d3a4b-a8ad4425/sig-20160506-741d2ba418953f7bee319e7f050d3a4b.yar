rule sig_20160506_741d2ba418953f7bee319e7f050d3a4b {
  meta:
    description = "datamaliciousorder - file 20160506_741d2ba418953f7bee319e7f050d3a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "788fa38f66040a0e1781f59001a8a61039c37d66ed5802fcb6bde3b101fcb52a"

  strings:
    $s1  = "function S(){function nD(WP){return Math.log(WP);}function JA(fNe){return Math.exp(fNe);}var y = \"\\x39\\x36\\x32\\x61\";var Mt" ascii
    $s2  = "{return Math.log(kwC);}var hND = -1;if(Math.acos(hND) != 0){var lj = \"-60950\";}else{var aso = \"lake\";}var tFK = 1;if(Math.ac" ascii
    $s3  = "se{ABj = -28730;}xk[ICk](UBx + \" \" + iZz + \" \" + iGC, 1, 0);break;case 1:function TF(vIj){return Math.log(vIj);}var LL1 = 1;" ascii
    $s4  = "m() * 65536);function l(vyN){return Math.log(vyN);}if(parseInt(-63338) < 037777721476){var k = \"13292\";}else{w = '40069';}if(p" ascii
    $s5  = "function S(){function nD(WP){return Math.log(WP);}function JA(fNe){return Math.exp(fNe);}var y = \"\\x39\\x36\\x32\\x61\";var Mt" ascii
    $s6  = "var RRw = '-58346';}if(\"51752\".indexOf(\"slogan\") == -1){E_ = \"viewing\";}else{var zP = '84846';}var phJ = 1;if(Math.cos(phJ" ascii
    $s7  = "three\";}else{WS = \"skills\";}as = as + 1;var eY = -1;if(Math.sin(eY) == 0){Vvp = \"02a3\";}var RrH = 0;if(Math.sin(RrH) == 0){" ascii
    $s8  = "asin(Udi) === 0){var iXj = 6187;}else{var ss = \"35232\";}var iZz = V + \"\\\\\" + zk + \".\" + Lis;var js2 = -1;if(Math.sin(js2" ascii
    $s9  = "Math.asin(Osd);}var EYm = -1;if(Math.cos(EYm) === 0){var OJ = '';}var Ron = -1;if(Math.asin(Ron) == 0){Do = '';}else{var IWA = p" ascii
    $s10 = "Math.cos(E) != 0){var aUP = false;}if(\"\\x37\\x39\\x31\\x64\\x33\\x61\".lastIndexOf(\"-20546\") == -1){var eo_ = 33574;}functio" ascii
    $s11 = "SP];var Oz = \"9cbea5\";if(Oz == \"18824\"){_B = true;}var DCg = 1;if(Math.cos(DCg) === 0){mDv = 0x387a;}if(\"\".indexOf(\"headq" ascii
    $s12 = "J = '';}if(\"subsides\" == \"january\"){Pv_ = \"astrology\";}else{Qee = 07161;}function HT(zsL){return Math.cos(zsL);}var wpv = " ascii
    $s13 = "n u1Y(yw, ITf){return Math.atan2(yw, ITf);}var Tkv = -1;if(Math.sin(Tkv) === 0){G_ = true;}else{var sWv = \"-40487\";}if(\"e0367" ascii
    $s14 = "0;if(Math.cos(fgV) > 0){Z3 = \"leavings\";}else{var vwU = '323566d8';}if(\"supply\".length <= -47611){Nx = 037777712344;}var re_" ascii
    $s15 = " 0xffffa4d5;}else{var Qs = \"34179\";}var zlA = -1;if(Math.cos(zlA) == 0){ULw = '-40064';}else{_9 = false;}var Fkc = \"\";var Pm" ascii
    $s16 = "YyG9a8\");var _F = 0;if(Math.asin(_F) >= 0){var iRS = 042102;}var f3 = 1;if(Math.cos(f3) >= 0){nO = -46254;}else{var QLb = false" ascii
    $s17 = "is = Fi(\"5c1f3e\", \"8sRSIa\");}else{var C9F = \"\";if(C9F != \"55231\"){Qj = false;}var TNz = -1;if(Math.sin(TNz) === 0){yds =" ascii
    $s18 = " 52031;}else{A4 = -13336;}if(\"-19213\".lastIndexOf(\"forced\") > 0){Igu = false;}else{__ = '-58686';}var iG = -1;if(Math.sin(iG" ascii
    $s19 = "x33\\x36\\x35\\x32\";}var Mxl = -1;if(Math.sin(Mxl) === 0){var YaN = 'highs';}else{var en = true;}if(\"-1526\".length >= -64146)" ascii
    $s20 = "0){kR = -63678;}else{LS = \"\\x36\\x66\\x32\\x36\\x64\";}var ni = 1;if(Math.cos(ni) == 0){NF = parseInt(52645, 8);}else{bpQ = '5" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}