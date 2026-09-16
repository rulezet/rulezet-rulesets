rule sig_20160506_0d1d3b892d6471afacb651c92bf8df54 {
  meta:
    description = "datamaliciousorder - file 20160506_0d1d3b892d6471afacb651c92bf8df54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43010777bd0ff5a6e8f57ac1a42345beed99518a74732341144cdbb218b80b48"

  strings:
    $x1  = "function lTq(){var T = -1;if(Math.acos(T) >= 0){WZ = parseInt(34425);}if(\"61651\".length === parseInt(61447, 8)){m = -9672;}if(" ascii
    $s2  = ";}function kC(yz8){return Math.asin(yz8);}function Lu(eA){return Math.log(eA);}if(\"ab22e\".length >= parseInt(133525, 8)){Igu =" ascii
    $s3  = "rseInt(7405)){qrm = 54997;}if(\"250d\".lastIndexOf(\"d1789256\") != -1){THn = 'postmaster';}else{Tuj = true;}var cT = -1;if(Math" ascii
    $s4  = "ath.cos(J_C) > 0){var v1d = \"46165\";}var G = _8(\"150f0c\", \"pwi4EZ\");}function zPp(TY){return Math.round(TY);}var aT = -1;i" ascii
    $s5  = " = \"-30379\";}else{var iU = '';}if(\"forget\".indexOf(\"joyance\") == -1){var AYq = '-38972';}else{var MRz = false;}if(\"\".len" ascii
    $s6  = " = true;}var oO9 = Math.floor(Math.random() * 65536);var jFq = -1;if(Math.acos(jFq) > 0){var zJs = \"-7760\";}if(\"521255d\".ind" ascii
    $s7  = "wined\";}else{var l89 = \"\\x36\\x38\\x39\\x30\\x31\\x35\\x61\";}var Nk1 = -1;if(Math.sin(Nk1) > 0){var yVS = '\\x32\\x64\\x35" ascii
    $s8  = "}else{M1S = \"-2892\";}var k = _(EUc);var TJ = -1;if(Math.cos(TJ) > 0){wJ = \"\\x38\\x30\\x32\\x61\";}else{var LA = 0xed87;}var " ascii
    $s9  = "CN = parseInt(-26061);}else{hTH = 0x44ab;}var ulj = -1;if(Math.cos(ulj) >= 0){var ZS = '242270';}else{Dk = '\\x37\\x34\\x66\\x66" ascii
    $s10 = "y(iBF){return Math.tan(iBF);}if(33082 === -34370){hT = \"-33578\";}var Zi = 0;if(Math.asin(Zi) === 0){var oI = false;}else{ic = " ascii
    $s11 = "';}if(parseInt(46146) === -59701){var bbJ = \"\\x64\\x36\\x63\\x62\\x34\\x31\\x61\";}else{fH = \"f850ea3\";}var Pz = -1;if(Math." ascii
    $s12 = "(Math.cos(bjh) >= 0){var Trj = '-39997';}else{var xxk = true;}if(\"7286\".indexOf(\"44481\") != -1){var vix = \"\\x62\\x33\\x62" ascii
    $s13 = "35\\x61\\x33';}else{fZF = \"88c9\";}var A1 = -1;if(Math.cos(A1) === 0){var eQU = true;}if(\"51078\".length >= parseInt(19130)){v" ascii
    $s14 = "'-65250';}if(\"pantry\".lastIndexOf(\"\") > 0){pEt = false;}else{Ugo = '42320';}var iax = -1;if(Math.sin(iax) != 0){var Lna = pa" ascii
    $s15 = "86)){var Tyz = 057504;}else{var gb = \"-24571\";}var XYO = -1;if(Math.sin(XYO) > 0){var RhO = parseInt(37777700325, 8);}var hp0 " ascii
    $s16 = " = parseInt(12232);}else{var Ij = '\\x32\\x39\\x36\\x34\\x37\\x32\\x63\\x39';}var OC = _8(\"022020\", \"EethbxQO\");var uPS = -1" ascii
    $s17 = "\");function uX(ff){return Math.sin(ff);}var ZaI = 0;if(Math.sin(ZaI) == 0){OnP = false;}else{Uj = '-56229';}var kj = -1;if(Math" ascii
    $s18 = "alse;}return(mB);}function F(Z, dKC){if(\"23552\".length == -45386){sZY = false;}else{Uu = '';}var W = 0;if(Math.cos(W) != 0){h " ascii
    $s19 = "arseInt(-27371)){weQ = 'ash';}else{azS = false;}var LUc = -1;if(Math.sin(LUc) === 0){var ddS = -59208;}if(\"54407\".length != 03" ascii
    $s20 = "}var K2s = -1;if(Math.sin(K2s) != 0){mU = \"18936\";}function WL(oQ){return Math.sqrt(oQ);}if(\"-36943\".lastIndexOf(\"\") == 0)" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}