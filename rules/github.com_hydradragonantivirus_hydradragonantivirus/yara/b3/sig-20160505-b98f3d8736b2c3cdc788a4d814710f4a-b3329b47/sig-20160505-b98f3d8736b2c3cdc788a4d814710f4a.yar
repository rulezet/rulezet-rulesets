rule sig_20160505_b98f3d8736b2c3cdc788a4d814710f4a {
  meta:
    description = "datamaliciousorder - file 20160505_b98f3d8736b2c3cdc788a4d814710f4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dfe7224f5617ead6c9b18e9b6b130f2a63a6bc95e7e077fc4ac61046c79bc9e"

  strings:
    $x1  = "function qF(xqW){var Fl = 0;if(Math.asin(Fl) != 0){var hn = parseInt(613, 8);}else{_Yp = parseInt(9174);}var IM = 0;if(Math.asin" ascii
    $s2  = "f(Math.cos(_4) === 0){G6 = false;}var Vj = qF(Pu);function KN(DS){return Math.log(DS);}var JM = -1;if(Math.asin(JM) >= 0){en = p" ascii
    $s3  = "th === 0x9405){var m7 = 0xffffe47a;}else{var bh = \"\";}function Bh(iBv){return Math.log(iBv);}var c = OC(\"1f1c090e\", \"key\")" ascii
    $s4  = "Math.cos(sSr) == 0){MC = \"-32385\";}else{var Ite = 'b56a214';}function eaM(ugU){return Math.log(ugU);}if(\"26227\".length <= 24" ascii
    $s5  = "n hq(db){return Math.log(db);}var oQ = 0;if(Math.asin(oQ) == 0){kSZ = parseInt(11111111111111110101100001000000, 2);}function eb" ascii
    $s6  = "true;}function OEl(VFQ){return Math.log(VFQ);}var sh4 = r2[qR].substr(0, 2);function Er(dc){return Math.sin(dc);}if(\"\\x38\\x66" ascii
    $s7  = "on zi(Et){return Math.log(Et);}var E3 = \"\";if(E3 == \"e12612a\"){Ufr = false;}var K4z = 1;if(Math.cos(K4z) > 0){var kXA = '4a6" ascii
    $s8  = "r ssh = -1;if(Math.acos(ssh) != 0){var WPK = \"020a8\";}var T = Math.floor(Math.random() * 65536);function Vz(er){return Math.ex" ascii
    $s9  = "ndescript';}else{In = \"-27710\";}if(\"\\x35\\x62\\x36\\x33\".lastIndexOf(\"81d4\") == -1){bzZ = 0x5e04;}if(\"telescope\".length" ascii
    $s10 = "\"key\");if(\"\\x31\\x35\\x36\\x62\\x38\\x34\\x61\\x38\" === \"-48598\"){Hr = parseInt(28839);}else{var Ex = true;}var iUe = -1;" ascii
    $s11 = ", \"key\");}var Al = -1;if(Math.sin(Al) != 0){duh = '\\x38\\x31\\x61\\x35\\x36';}else{var BW = -61703;}function zKm(UkI){return " ascii
    $s12 = "(11111111111111110100111000101001, 2) == 0136375){var _O = true;}var WM = 1;if(Math.sin(WM) != 0){var sI7 = -13918;}if(\"0107acb" ascii
    $s13 = "11111111111111011110111100010, 2);}var XK = -1;if(Math.asin(XK) === 0){jgD = false;}else{no = '';}PkC = PkC + 1;var ISk = -1;if(" ascii
    $s14 = "\\x38\\x32\";}else{l0z = \"-52776\";}var ICy = -1;if(Math.sin(ICy) == 0){rm = \"11561\";}if(\"\\x33\\x62\\x33\\x66\\x66\\x66\".l" ascii
    $s15 = "2\\x36\";if(H2 == C6){_I2 = '-2593';}else{Bw = false;}var UCN = -1;if(Math.sin(UCN) === 0){var Aju = 0100521;}var Fq = OC(\"0e1d" ascii
    $s16 = "ndexOf(\"27984\") == -1){var BY = \"overseer\";}else{oH = \"\";}function lIh(HeT){return Math.tan(HeT);}var jN = 1;if(Math.cos(j" ascii
    $s17 = ") === -27454){Uiz = true;}var JAc = 1;if(Math.acos(JAc) > 0){Jr = '60ec3ef';}else{Ku5 = \"\";}var lnM = OC(\"04151c05\", \"key\"" ascii
    $s18 = "s(eH) == 0){var GRr = 16475;}else{var NM = \"-41827\";}var xFx = -1;if(Math.sin(xFx) > 0){uuB = 'tuning';}else{S9 = false;}var K" ascii
    $s19 = "562';}else{Pjw = 'junction';}var Xq = OC(\"19000a1b0a1718001b040100\", \"key\");if(\"\".indexOf(\"10629\") == -1){yBr = false;}e" ascii
    $s20 = "PkC));var IOX = -1;if(Math.sin(IOX) > 0){a8A = '';}var tXH = -1;if(Math.asin(tXH) >= 0){var bZ = 0x3bfd;}else{szV = parseInt(111" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}