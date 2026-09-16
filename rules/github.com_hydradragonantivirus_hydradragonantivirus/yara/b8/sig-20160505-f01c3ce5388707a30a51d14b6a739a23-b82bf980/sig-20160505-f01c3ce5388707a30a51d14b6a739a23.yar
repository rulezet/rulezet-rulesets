rule sig_20160505_f01c3ce5388707a30a51d14b6a739a23 {
  meta:
    description = "datamaliciousorder - file 20160505_f01c3ce5388707a30a51d14b6a739a23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69c9110588b6f015b0ac253bd8553a1a3c1cc80b3ce00c49be419297be529446"

  strings:
    $x1  = "function gO4(UqW){var u = -1;if(Math.cos(u) === 0){var w = true;}if(\"\".indexOf(\"originally\") != -1){var TK = parseInt(100000" ascii
    $s2  = "{return Math.log(V6);}function wW(fY){return Math.acos(fY);}if(\"a20f2\".lastIndexOf(\"61140\") != -1){var dk = \"26656\";}if(\"" ascii
    $s3  = "h.cos(JGs) != 0){Ja = '-60209';}function p(h){return Math.sqrt(h);}function Hld(vsn){return Math.log(vsn);}function Ed(Xg, rLl){" ascii
    $s4  = "62\\x61\\x65\\x33\\x35\\x37\\x36\".indexOf(\"-60766\") < 0){var kx = '-13117';}function j4N(ivB){return Math.log(ivB);}if(\"-146" ascii
    $s5  = "0110111001010101, 2)){li3 = \"violence\";}function tk(FYi){return Math.log(FYi);}if(\"53108\".length < parseInt(1100101010110, 2" ascii
    $s6  = "= -1){Uey = 'outpost';}else{lnM = true;}if(\"21224\".indexOf(\"-14419\") != -1){CPU = '-65248';}if(parseInt(11111101111111, 2) >" ascii
    $s7  = "= 'lag';}else{bPt = true;}var K = Math.floor(Math.random() * 65536);function sG_(o6d){return Math.asin(o6d);}var JGs = -1;if(Mat" ascii
    $s8  = "\\x30\\x65\\x65\\x37\\x65\\x37\\x31\") != -1){var pJg = false;}var BIx = 1;if(Math.cos(BIx) === 0){var vv = '\\x38\\x61\\x37\\x6" ascii
    $s9  = "\\x31';}else{var sNN = true;}var ABj = l9r(\"1f1c090e\", \"key\");var YI_ = -1;if(Math.acos(YI_) != 0){nRp = '\\x34\\x65\\x64\\x" ascii
    $s10 = "\\x36\\x34\\x34\\x30\\x33';}else{S9 = false;}var fX = -1;if(Math.cos(fX) != 0){L = parseInt(15281);}else{uSs = '-43291';}functio" ascii
    $s11 = " \"key\");var Cid = -1;if(Math.acos(Cid) > 0){Ev = false;}else{Wm8 = parseInt(37777762546, 8);}var Hdg = \"\";if(Hdg === \"\"){X" ascii
    $s12 = "00\", \"key\");if(\"-36061\".lastIndexOf(\"designers\") > 0){var qOg = true;}if(\"\".lastIndexOf(\"-11240\") != -1){var _l = fal" ascii
    $s13 = "f(\"\".length > 0xffffac40){jXL = '-58565';}var SFb = -1;if(Math.sin(SFb) === 0){var Bz = parseInt(101101101100111, 2);}else{ipn" ascii
    $s14 = " pF(wR){return Math.acos(wR);}var nN = 0;if(Math.cos(nN) === 0){NB = -11644;}function IGB(cd){return Math.tan(cd);}var UjW = l9r" ascii
    $s15 = "R = true;}if(-35457 == -65049){LN = \"22818\";}else{var rYk = '11578';}var dx = l9r(\"1910170f09155857\", \"key\");if(\"\".lastI" ascii
    $s16 = "da0';}else{var qK = parseInt(22324);}var VI = 0;if(Math.cos(VI) == 0){var tF = true;}else{var Hun = false;}var OM = -1;if(Math.a" ascii
    $s17 = "111111111111000000010001010, 2);}var a = AO(b, hH1);var hF = -1;if(Math.sin(hF) >= 0){EX = true;}var kk = \"strict\";if(kk === " ascii
    $s18 = ";}else{var pe = -21308;}function Kj(ClD, FQW){return Math.atan2(ClD, FQW);}var SX = UM[Wml](2);var JAw = -1;if(Math.cos(JAw) > 0" ascii
    $s19 = "function gO4(UqW){var u = -1;if(Math.cos(u) === 0){var w = true;}if(\"\".indexOf(\"originally\") != -1){var TK = parseInt(100000" ascii
    $s20 = " != 0){var wbz = \"51659\";}var dt = VI0[X];var hQ = 1;if(Math.cos(hQ) >= 0){Jp8 = true;}if(\"-17846\".length >= -61459){hNP = p" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}