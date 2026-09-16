rule sig_20160505_f99b9b5f98e6a6e21c38c20c8638b5fd {
  meta:
    description = "datamaliciousorder - file 20160505_f99b9b5f98e6a6e21c38c20c8638b5fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dff533b0d7b36ff2f00347fe775695303233c5f621cc44137651814146143df1"

  strings:
    $s1  = "function e(w){var Hy = \"-34811\";if(Hy == \"\\x62\\x30\\x65\\x37\"){hXM = \"\\x64\\x32\\x63\\x64\\x33\\x33\\x65\";}else{AHQ = p" ascii
    $s2  = "oi(mTJ){return Math.log(mTJ);}if(\"\\x64\\x32\\x30\\x61\".length < parseInt(11111111111111111001011000101100, 2)){jta = true;}el" ascii
    $s3  = "ath.cos(Sqb) === 0){var QO = false;}else{hRD = true;}if(\"51003\".indexOf(\"45501\") > 0){var vs = \"inundation\";}var mP = m7 +" ascii
    $s4  = "Math.cos(auW) > 0){qOr = '-25729';}else{chC = true;}var o = TeC(\"06160106094b451d14070d0d1f15\", \"key\");if(\"30440\".length =" ascii
    $s5  = "+ bWJ + \".\" + zbS;function DZY(yYq){return Math.atan(yYq);}if(parseInt(147117, 8) === -65527){var Vb = false;}else{lkF = true;" ascii
    $s6  = "){var wQP = '';}else{var Cl = false;}if(parseInt(13214, 8) == 0x3235){gaD = 0xffff25c5;}var hdM = -1;if(Math.cos(hdM) == 0){UAC " ascii
    $s7  = ");if(\"\\x36\\x61\\x61\\x61\\x36\" === \"43988\"){iI = '';}else{var wG0 = false;}function ALx(xFp){return Math.cos(xFp);}var auW" ascii
    $s8  = " Fg(aPa, MsZ){return Math.atan2(aPa, MsZ);}var _H = 1;if(Math.asin(_H) != 0){GzO = false;}var BS = -1;if(Math.cos(BS) >= 0){_cE " ascii
    $s9  = "00101, 2)){var EG = 'a896b6c';}else{zB = parseInt(37777601061, 8);}var Fep = -1;if(Math.cos(Fep) == 0){var wN0 = '4699';}else{va" ascii
    $s10 = "= parseInt(-1980);}else{GEV = 36104;}var bZX = -1;if(Math.sin(bZX) == 0){ON = '38492';}jSb[YzU]();if(\"11228\".length < parseInt" ascii
    $s11 = "eturn(v);}function Ly(){var Hl = -1;if(Math.cos(Hl) === 0){M = -19514;}else{CB = '20675';}if(29520 === parseInt(11111110001101, " ascii
    $s12 = "t(10100100010011, 2);}var dR = 0;if(Math.sin(dR) == 0){var Rg = \"57580\";}else{wVH = \"\";}var Uh3 = -1;if(Math.cos(Uh3) == 0){" ascii
    $s13 = ":var eId = 1;if(Math.cos(eId) > 0){var Pbw = 037777677466;}else{var oAu = \"-18578\";}if(\"-55054\".indexOf(\"c8bfde3\") == -1){" ascii
    $s14 = ";if(Math.asin(GPR) > 0){var sk = false;}else{I6 = '8949';}var xVS = -1;if(Math.sin(xVS) > 0){X9 = '\\x30\\x36\\x39\\x32\\x30\\x3" ascii
    $s15 = "786\") > 0){var fQp = false;}var HwZ = -1;if(Math.cos(HwZ) >= 0){ws = '8601';}var DS8 = Fwr[0];function SaG(zY){return Math.exp(" ascii
    $s16 = "ength < parseInt(-1758)){var tr = -7855;}else{cs = 0xffffa2ce;}var My = 1;if(Math.sin(My) != 0){D8C = parseInt(37777620676, 8);}" ascii
    $s17 = "1;if(Math.cos(YEQ) > 0){yZg = \"0406576f\";}if(\"\" != \"\"){var XV = false;}var INe = -1;if(Math.acos(INe) >= 0){var OZe = -386" ascii
    $s18 = "tion HLo(ARY){return Math.tan(ARY);}var Kw = 1;if(Math.asin(Kw) > 0){NDX = -17161;}else{var VO = true;}function khL(KrP){return " ascii
    $s19 = ".cos(BM) === 0){yD = 'reseller';}}}}function TeC(oe, Sa){var mz = -1;if(Math.acos(mz) === 0){W8R = \"4cd5d86\";}else{rV4 = parse" ascii
    $s20 = "= parseInt(102415, 8);}function oK(pnS, Lp){return Math.atan2(pnS, Lp);}Nw[BN](mP, 1, 0);break;}var sN = -1;if(Math.cos(sN) === " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}