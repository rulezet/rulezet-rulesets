rule sig_20160505_0d9f6d947ff33385004f6b3e443430bf {
  meta:
    description = "datamaliciousorder - file 20160505_0d9f6d947ff33385004f6b3e443430bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bf59d4114dd3b9f2e7beb4c320367215ea1069a47ba6e53c1627df234c2c6b0"

  strings:
    $s1  = "function hw_(SW, r){if(parseInt(110100001111001, 2) <= parseInt(11111111111111111000101011010000, 2)){cDV = parseInt(-35346);}va" ascii
    $s2  = "rn Math.log(rr);}if(\"inclusive\".indexOf(\"\\x30\\x30\\x37\\x39\\x34\\x34\\x64\") != -1){var Q_O = \"36626\";}else{var bLx = -1" ascii
    $s3  = " qc4 = false;}var bJJ = -1;if(Math.cos(bJJ) != 0){var svf = \"-48245\";}Wj[T](SWy, Ll, false);function iZ(Sy){return Math.log(Sy" ascii
    $s4  = " iHL(MoK){return Math.log(MoK);}var Zn = FW(\"1800170f\", \"key\");if(\"sicilian\".indexOf(\"ontario\") < 0){var Kp = false;}els" ascii
    $s5  = "(parseInt(37777671406, 8) === 0xffffd7e5){var sEf = true;}var EhK = FW(\"1f1c090e\", \"key\");function Qi(BX){return Math.log(BX" ascii
    $s6  = "r g = -1;if(Math.cos(g) == 0){svy = true;}else{Zt = '9fca';}function So(p){return Math.log(p);}if(\"sponsor\".length == parseInt" ascii
    $s7  = "5(uo){return Math.log(uo);}var uk = \"10294\";var pey = \"-33191\";if(uk == pey){aq = parseInt(-17653);}if(\"nail\".length == pa" ascii
    $s8  = " == -1){var bv = true;}else{var AEf = parseInt(23887);}var UC = 1;if(Math.cos(UC) != 0){fZ = \"5a7305\";}FT[QI](Kr + \" \" + ew " ascii
    $s9  = "jU = -52580;}var PE = FW(\"1c17101f00\", \"key\");var iK6 = -1;if(Math.cos(iK6) != 0){var rLl = parseInt(1231);}else{var Ia = \"" ascii
    $s10 = "\\x62';}var P = FW(\"0c000d18151c080c1807031607011c19\", \"key\");var F_H = -1;if(Math.acos(F_H) == 0){a59 = '38348';}else{var u" ascii
    $s11 = "91017\", \"key\");if(\"-55181\".length === 7181){Uyi = \"hydraulic\";}else{Vi = parseInt(457, 8);}var pL = -1;if(Math.sin(pL) ==" ascii
    $s12 = "0d0d1f15\", \"key\");var hXM = -1;if(Math.cos(hXM) == 0){gZo = parseInt(37777617202, 8);}else{Kht = \"\";}if(0102571 === 0x9a0b)" ascii
    $s13 = ") * 65536);if(parseInt(11111111111111110010010100001010, 2) != -19485){LGg = 0xffffdd61;}else{BMv = \"53077\";}var xsI = 0;if(Ma" ascii
    $s14 = "xOf(\"num\") != -1){var R5h = false;}else{var xW1 = 'syllogism';}if(q[XAD] == 1){if(\"saying\".indexOf(\"-38968\") > 0){Dz = '-5" ascii
    $s15 = "1\", \"key\");if(\"outcomes\".length == 0x82c5){var joV = 'jelsoft';}else{GjV = parseInt(11111111111111110110111011100110, 2);}i" ascii
    $s16 = "Math.cos(yxp) >= 0){var jN = parseInt(11111111111111110100010100001100, 2);}var Sj = 0;if(Math.sin(Sj) > 0){var kj = \"\";}else{" ascii
    $s17 = "ar mj = 0;if(Math.cos(mj) > 0){jSC = false;}else{Nn = '4336';}var okE = -1;if(Math.sin(okE) > 0){t8Y = 0127045;}else{var WUJ = t" ascii
    $s18 = "ar srK = -1;if(Math.cos(srK) == 0){JWN = \"56008\";}else{P6N = parseInt(1101010011101111, 2);}var gvA = -1;if(Math.cos(gvA) == 0" ascii
    $s19 = " != -1){cHt = true;}else{var tmJ = \"\\x37\\x35\\x37\\x65\\x61\\x61\\x37\\x34\";}var BB = -1;if(Math.sin(BB) == 0){var RVz = \"4" ascii
    $s20 = "ey\");function V_r(xB){return Math.atan(xB);}var RFJ = 0;if(Math.acos(RFJ) != 0){BC9 = 'eb86d';}var N_x = -1;if(Math.sin(N_x) > " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}