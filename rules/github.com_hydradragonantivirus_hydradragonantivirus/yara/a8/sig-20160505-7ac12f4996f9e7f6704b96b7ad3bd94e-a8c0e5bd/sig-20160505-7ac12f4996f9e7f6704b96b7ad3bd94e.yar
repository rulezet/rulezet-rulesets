rule sig_20160505_7ac12f4996f9e7f6704b96b7ad3bd94e {
  meta:
    description = "datamaliciousorder - file 20160505_7ac12f4996f9e7f6704b96b7ad3bd94e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c051733a4a1e7641c92a6483d2bd4186a961c53229c2f4969a5a65f00e3e413"

  strings:
    $x1  = "function gre(){if(\"botanist\".indexOf(\"\\x61\\x34\\x64\\x38\\x39\") == 0){Nn = '8cd9';}if(\"\".length <= parseInt(2372, 8)){va" ascii
    $s2  = "on wt(Nmi){return Math.log(Nmi);}var bJ = -1;if(Math.sin(bJ) === 0){Yi = parseInt(1100110010000, 2);}if(\"-1778\".length === par" ascii
    $s3  = "= \"\";}function wST(zKm){return Math.log(zKm);}var GDW = VR(VBo);if(\"46903\".length > parseInt(-40960)){var kP = \"64\";}if(\"" ascii
    $s4  = "cos(H4s);}var sD = k(\"1f1c090e\", \"key\");function lg(Rm, avL){return Math.atan2(Rm, avL);}var cF = -1;if(Math.sin(cF) > 0){va" ascii
    $s5  = "ath.asin(vix) === 0){bJq = '\\x39\\x39\\x31\\x65\\x64\\x65\\x33';}else{var Ex1 = 0xffffefcd;}var gfn = -1;if(Math.sin(gfn) >= 0)" ascii
    $s6  = "ath.ceil(mpx);}var zUM = -1;if(Math.sin(zUM) === 0){var tv2 = 0xffff772f;}else{XJc = true;}if(0x1fa5 === parseInt(-7680)){kX = " ascii
    $s7  = ";}if(\"0118\".length >= parseInt(11111111111111110001101011001001, 2)){var D_ = '';}else{XPN = '-15057';}var gUq = -1;if(Math.si" ascii
    $s8  = "Math.asin(AX2) === 0){var kS = true;}if(\"anthropology\" === \"-25012\"){SwQ = \"\\x64\\x64\\x65\\x34\\x39\\x35\";}var XKz = XKz" ascii
    $s9  = "r QMQ = parseInt(11111111111111110100001101111101, 2);}else{var UP = '';}var _jI = k(\"191017\", \"key\");var T4 = 1;if(Math.cos" ascii
    $s10 = "astIndexOf(\"-1141\") < 0){NZ = \"21177\";}var L = Aw + \"\\\\\" + wZS + \".\" + dSk;if(parseInt(1101110011010100, 2) <= -9138){" ascii
    $s11 = ";}function ZQR(dV_){return Math.tan(dV_);}if(\"encountered\".length < -42555){var Dv = -55519;}else{e = 712;}var eP = -1;if(Math" ascii
    $s12 = "alse;}if(Sbl[V] == 1){var niS = -1;if(Math.cos(niS) != 0){var sph = false;}var qT = 1;if(Math.cos(qT) > 0){var Riz = '632a';}if(" ascii
    $s13 = "9255c5\";}else{nWj = \"lookup\";}var v3 = -1;if(Math.acos(v3) != 0){DGX = '\\x39\\x65\\x63\\x35\\x31\\x66';}else{var hX = parseI" ascii
    $s14 = "{var eBw = \"europa\";}var Cxz = 0;if(Math.asin(Cxz) > 0){var Qi = 0373;}else{TL_ = -63011;}var zuP = -1;if(Math.cos(zuP) == 0){" ascii
    $s15 = " cd);}var XtQ = -1;if(Math.cos(XtQ) >= 0){kf = false;}var l_ = \"generator\";if(l_ != \"\\x32\\x30\\x65\\x61\\x38\"){var xfx = '" ascii
    $s16 = " TGw = -1;if(Math.acos(TGw) == 0){Pjj = true;}var faw = 0;if(Math.sin(faw) === 0){var t9 = \"payment\";}else{vXA = \"-43926\";}v" ascii
    $s17 = "}finally{var Vt1 = false;}var Vp = k(\"06160106094b451d14070d0d1f15\", \"key\");var GwY = -1;if(Math.asin(GwY) != 0){Gmv = 01324" ascii
    $s18 = "tion yhN(ZRW){return Math.exp(ZRW);}var ai = -1;if(Math.asin(ai) >= 0){D8 = false;}else{var mk4 = \"14385\";}if(\"16431\".indexO" ascii
    $s19 = ") >= 0){var aW0 = '\\x33\\x64\\x34\\x33';}var TW = -1;if(Math.cos(TW) === 0){var xmO = true;}else{var _Lp = '56024';}try{KrV = " ascii
    $s20 = "2579';}else{var T_B = 0x6b97;}function oKQ(Hna){return Math.ceil(Hna);}var ZyW = -1;if(Math.sin(ZyW) > 0){var Vq = \"51288114\";" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}