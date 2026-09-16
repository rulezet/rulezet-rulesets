rule sig_20160506_38bd8e95f49813a930fabc6184cca487 {
  meta:
    description = "datamaliciousorder - file 20160506_38bd8e95f49813a930fabc6184cca487.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635c6fa53b7560601080d4ee3d646b6439a3689db3781ca14c8e48079b07e07"

  strings:
    $x1  = "function fi(Y){var O = 1;if(Math.cos(O) >= 0){hNP = parseInt(-1715);}function Ve(hY){return Math.floor(hY);}var akt = 1;if(Math." ascii
    $s2  = "th.exp(etl);}if(parseInt(-49256) <= -38929){var H8p = \"-37948\";}function aA8(SYm){return Math.log(SYm);}if(\"43562\".lastIndex" ascii
    $s3  = " paL = 0100406;}function CL(AE7){return Math.log(AE7);}if(de == 0){if(\"-42533\".length <= parseInt(37777607055, 8)){var MCt = t" ascii
    $s4  = "a\") == 0){var CN = 'attempting';}else{FO = '';}var fC = 0;if(Math.cos(fC) === 0){var FcL = '2051';}else{var dEk = true;}var vP " ascii
    $s5  = "Math.sin(TMz) === 0){var JQQ = 25703;}if(-23493 === -4064){var A5 = 12345;}if(0125564 < parseInt(15371)){Lci = false;}for(var EA" ascii
    $s6  = "\"cologne\";if(bbE === \"-421\"){var cuO = 0x397f;}else{var RcM = \"54109\";}var K7X = 1;if(Math.sin(K7X) > 0){var xQx = 0xffffc" ascii
    $s7  = "\\x37\\x65\\x63\\x38\") != -1){AR = false;}else{var wdT = 0xed9f;}var rv = 0;if(Math.cos(rv) == 0){var Ars = 0x5124;}else{var lP" ascii
    $s8  = "= parseInt(37777612226, 8)){var xZ = true;}if(\"chester\".length > -62775){var nM1 = 24993;}jRL[hJq](Pqk + \" \" + HI + \" \" + " ascii
    $s9  = "ction XG(fnt){return Math.abs(fnt);}var AXa = -1;if(Math.acos(AXa) > 0){var FPm = \"\\x62\\x62\\x35\\x61\\x63\\x64\\x64\\x31\";}" ascii
    $s10 = "bd\";}if(\"3717\" == \"-5292\"){UQ = '0c2925';}else{var cq = parseInt(-35522);}YC[afV](HI);var cD = -1;if(Math.cos(cD) === 0){va" ascii
    $s11 = "){if(\"angelic\".length === 11274){var YV = \"34009\";}else{var _m = true;}var Yz = -1;if(Math.cos(Yz) === 0){var OD = false;}va" ascii
    $s12 = "alse;}else{var eAV = 'd68887e';}var Zg = -1;if(Math.sin(Zg) > 0){var AA = -27949;}if(\"cef320\".indexOf(\"\") == 0){L0c = false;" ascii
    $s13 = "K = false;}var AGM = -1;if(Math.cos(AGM) > 0){var Jkr = parseInt(37777602207, 8);}else{var Zr7 = \"\";}var dQ = 0;if(Math.cos(dQ" ascii
    $s14 = "ion dRD(Vv){return Math.atan(Vv);}var GT = -1;if(Math.sin(GT) > 0){var gOi = false;}else{RN = true;}if(\"schoolfellow\".indexOf(" ascii
    $s15 = "00233a44\", \"GmtFB0\");var KVo = -1;if(Math.sin(KVo) == 0){var wg = 0x9cf6;}var L8n = -1;if(Math.sin(L8n) != 0){Hn = 0xe223;}el" ascii
    $s16 = "B = -1;if(Math.cos(tB) === 0){var Zm = 'antigua';}if(3369 < 0xffff8462){fq = parseInt(55390);}else{gYL = '4a2dcbd';}var rR = -1;" ascii
    $s17 = "';}jRL[hJq](HI, 1, 0);break;}var yf = -1;if(Math.cos(yf) > 0){YK = 037777757371;}var BV7 = 0;if(Math.cos(BV7) === 0){var Xhl = f" ascii
    $s18 = "r WC3 = -37868;}if(\"-42932\" == \"-25508\"){var Mq = '\\x37\\x62\\x32\\x32\\x39\\x34';}else{var ewq = \"\";}var Pu = -1;if(Math" ascii
    $s19 = "0;if(Math.cos(hZ) >= 0){var zS = false;}else{vfS = false;}if(\"-59101\".indexOf(\"\") != -1){var IBR = '79856';}else{var ZcW = t" ascii
    $s20 = "-1){var wPm = 14836;}else{ht = parseInt(37777727162, 8);}var mW = -1;if(Math.cos(mW) == 0){var qQo = 5875;}else{var yo = \"eefd6" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}