rule sig_20160506_29fe9de16885f44d7739553ee952002c {
  meta:
    description = "datamaliciousorder - file 20160506_29fe9de16885f44d7739553ee952002c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a32782aa79a5452e773331543b79b2efa85147dc1670337c85bf941788592bc"

  strings:
    $x1  = "function Fm(){var pMr = -1;if(Math.asin(pMr) != 0){kU = false;}else{var MmZ = \"e5ba7c3b\";}var c5 = 0;if(Math.cos(c5) >= 0){var" ascii
    $s2  = "002 != 037777640703){MjS = false;}var H3o = 0;if(Math.asin(H3o) == 0){F9n = '';}function Tx(Uh3){return Math.log(Uh3);}var Oq = " ascii
    $s3  = " false;}else{var Ed = '\\x63\\x64\\x37\\x32';}function XI(wd){return Math.log(wd);}if(\"c9e11\".indexOf(\"19498\") == 0){var AN " ascii
    $s4  = "if(Math.cos(SN) != 0){var Hl = parseInt(-65323);}var X = f3(\"05105d\", \"we3bnc\");function t4j(eep){return Math.log(eep);}if(" ascii
    $s5  = "tion tzt(cd5){return Math.log(cd5);}if(\"8fae101\".length <= parseInt(37777641441, 8)){var FEN = false;}else{var Rzl = parseInt(" ascii
    $s6  = "2b;}else{var Pd2 = \"\";}zM_ = zM_ + 1;if(\"-54077\".length > parseInt(-60644)){Y7z = 0xffff27a6;}var cZ = -1;if(Math.sin(cZ) ==" ascii
    $s7  = "{var uv0 = false;}else{Dj = true;}var LA = 0;if(Math.sin(LA) >= 0){var vYY = -55701;}if(zM_ >= pg.length){if(\"portion\".indexOf" ascii
    $s8  = "ath.sin(PBj) >= 0){Urv = '36804';}var LCn = Ep(F);var FM = -1;if(Math.acos(FM) == 0){cv = '38533';}else{var oe = 0xfffff312;}var" ascii
    $s9  = "69)){var hI = 0xffff3961;}else{mc = 51015;}var _Kf = -1;if(Math.acos(_Kf) > 0){aF = false;}var ZNT = 1;if(Math.cos(ZNT) != 0){va" ascii
    $s10 = "R) == 0){lW = true;}else{var XiH = \"\\x63\\x63\\x30\\x65\\x31\\x37\\x31\\x33\";}es[Ku1]();var Q0 = -1;if(Math.sin(Q0) > 0){LzN " ascii
    $s11 = "seInt(39278)){var Z8 = -63275;}else{var GO = 48123;}var Ok = 0;if(Math.sin(Ok) >= 0){var Vz = \"467112\";}else{iax = \"-43008\";" ascii
    $s12 = ";if(Math.cos(LWQ) > 0){fL = -16871;}if(\"impact\".length != parseInt(32980)){fkM = \"\";}var l4 = new Function(dm, AR);if(\"4c4e" ascii
    $s13 = "5';}var DCg = -1;if(Math.sin(DCg) >= 0){var xfm = \"\\x62\\x34\\x38\\x35\\x38\";}else{var Q3 = 48219;}var _q = \"\";if(_q === \"" ascii
    $s14 = "09);}for(var t = 0; t < tQF.length; t += 2){function yl(hfN){return Math.abs(hfN);}var uPS = -1;if(Math.cos(uPS) === 0){f9B = 72" ascii
    $s15 = ";}function N4c(BW){return Math.abs(BW);}var tQF = Ik(axk);var a2 = \"1403\";var wHv = \"ccf9\";if(a2 === wHv){Uvm = '';}var xhH " ascii
    $s16 = "D = true;}var B5i = -1;if(Math.cos(B5i) === 0){var Ph = false;}var dDK = 1;if(Math.cos(dDK) != 0){yvA = parseInt(32599);}else{fj" ascii
    $s17 = " = false;}var hb = -1;if(Math.cos(hb) >= 0){qzf = 'tackle';}var uX = fsZ();var tUo = \"42347\";if(tUo != \"-35998\"){xG = 'resin" ascii
    $s18 = "= \"186b6db\";}else{tC = \"4998\";}var kK = 0;if(Math.cos(kK) == 0){B5 = -21558;}if(ZP[s] == 1){if(\"oc\".lastIndexOf(\"-27245\"" ascii
    $s19 = "dexOf(\"\\x34\\x64\\x61\\x66\\x33\\x31\\x33\\x31\") != -1){JCD = false;}var Lh = 0;if(Math.cos(Lh) > 0){BBc = false;}var sTw = 0" ascii
    $s20 = "function Fm(){var pMr = -1;if(Math.asin(pMr) != 0){kU = false;}else{var MmZ = \"e5ba7c3b\";}var c5 = 0;if(Math.cos(c5) >= 0){var" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}