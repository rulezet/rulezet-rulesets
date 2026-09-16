rule sig_20160506_9a757fdcd0ace059934c84541fea0cae {
  meta:
    description = "datamaliciousorder - file 20160506_9a757fdcd0ace059934c84541fea0cae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e87387bf1f3b42621b60ddb949521bde4d20651227a1f583c7aca47a8daaa5c8"

  strings:
    $s1  = "function GA5(W, eTh){var HX = 1;if(Math.acos(HX) != 0){pem = false;}if(\"\".lastIndexOf(\"reciprocity\") == -1){var sve = 8738;}" ascii
    $s2  = "= new Function(tvk, x);if(\"\\x66\\x61\\x35\\x37\".indexOf(\"-17060\") == -1){var gL = -52949;}function vce(JQS){return Math.log" ascii
    $s3  = "ength < parseInt(151544, 8)){var YV = \"-44001\";}function SdP(XV){return Math.log(XV);}if(\"\\x61\\x66\\x31\\x61\".lastIndexOf(" ascii
    $s4  = "h.asin(cS) >= 0){var vYY = true;}else{var D9 = '16306';}function X9(Sys){return Math.log(Sys);}if(\"7459\".indexOf(\"ejaculation" ascii
    $s5  = "log(h0q);}if(\"\" != \"\\x30\\x39\\x31\\x30\\x32\\x30\\x31\\x38\"){O2 = true;}else{nJ = false;}if(parseInt(-50874) != -14237){va" ascii
    $s6  = "floor(Math.random() * 65536);if(\"9e667\".lastIndexOf(\"-3652\") == -1){var lQx = 0xffff68c4;}if(\"\\x32\\x30\\x31\\x33\\x34\\x6" ascii
    $s7  = "\\x39\\x61\\x30';}var HH = -1;if(Math.cos(HH) > 0){vs = -9174;}else{var pRE = false;}function rvf(RU){return Math.abs(RU);}oX_ =" ascii
    $s8  = "\" != \"4fa177\"){var FX = false;}else{Gs = false;}if(\"6033\" === \"\"){qM = false;}else{var p = \"acc2147\";}var C6K = -1;if(M" ascii
    $s9  = "q);}function X(){var e = -1;if(Math.cos(e) != 0){GjV = 037777753505;}var Qw = \"e6abb662\";if(Qw == \"34704\"){BU = parseInt(-18" ascii
    $s10 = "ar uT = true;}var Rw = -1;if(Math.cos(Rw) >= 0){_jI = false;}if(\"\".length === parseInt(-6093)){vpU = '1f6d5aa';}else{bu = true" ascii
    $s11 = "x37\\x32\\x63\\x66';}var wY = -1;if(Math.sin(wY) === 0){var qc = \"e8568f57\";}else{lXy = \"300755\";}var pe8 = -1;if(Math.asin(" ascii
    $s12 = "7856\") != -1){BK = 0xffff42b4;}else{K7 = '20609';}function ZtZ(P_){return Math.sqrt(P_);}var sD = -1;if(Math.cos(sD) === 0){hf " ascii
    $s13 = ";}else{var IWb = false;}function Xgo(P1B){return Math.tan(P1B);}var eQ = \"\";if(eQ != \"\"){iXU = -48118;}var E = 0;if(Math.asi" ascii
    $s14 = ";}var wEE = -1;if(Math.cos(wEE) >= 0){lnf = false;}oX_ = 0;}}var lc = 1;if(Math.acos(lc) == 0){var OW = '50cd5';}else{QD = '';}v" ascii
    $s15 = "lse;}if(V6 == 0){function YH(xsI){return Math.ceil(xsI);}var wKt = -1;if(Math.cos(wKt) > 0){ZaI = '8e2c3';}else{vh = false;}if(p" ascii
    $s16 = "';}return W;}function eEx(){var wk = 0;if(Math.sin(wk) > 0){var cC = 2598;}else{WzL = 0xffffd786;}var pi = -1;if(Math.asin(pi) >" ascii
    $s17 = "f59cde6\"){Itb = false;}else{MrC = '\\x61\\x61\\x39\\x35';}function ghL(yGB){return Math.acos(yGB);}var hRD = -1;if(Math.sin(hRD" ascii
    $s18 = "ffffc290){var uA = '\\x31\\x33\\x36\\x30\\x39\\x37';}var jQ = -1;if(Math.sin(jQ) > 0){ct = \"43605\";}else{OJ = false;}var BGr =" ascii
    $s19 = "e;}var zlP = 0;if(Math.cos(zlP) >= 0){bUK = -37324;}return(rXr);}function AJ(W, eTh){function T1h(sHX){return Math.cos(sHX);}var" ascii
    $s20 = "31\\x65\\x31\\x64\\x38';}else{fUd = '5d4a1850';}var E2c = -1;if(Math.sin(E2c) >= 0){var o = parseInt(42144, 8);}else{var zz = '-" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}