rule sig_20160505_525ad0812c4225d114f99fff05037968 {
  meta:
    description = "datamaliciousorder - file 20160505_525ad0812c4225d114f99fff05037968.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f946caa3b924d41e7fabedcba8fadf07c9958d67aa33b6ed7e0c37831a4a1c"

  strings:
    $x1  = "function O(f){var Wa = \"-61288\";var h = \"\";if(Wa === h){var Ww = '';}else{n = '\\x62\\x37\\x30\\x62';}if(parseInt(60284) == " ascii
    $s2  = "\"\\x36\\x64\\x65\\x66\\x39\";}function JBx(cKW){return Math.log(cKW);}var L6U = WW(ixK);var Ra = -1;if(Math.sin(Ra) == 0){NOX =" ascii
    $s3  = "eturn Math.log(kGe);}if(\"0b99\".length < 037777744010){var vL = 'entity';}else{rxl = '';}var CSu = rhj(\"1910170f09155857\", \"" ascii
    $s4  = "= true;}else{var yaL = '';}function tF(qY){return Math.log(qY);}var UAl = rhj(\"19000a1b0a1718001b040100\", \"key\");if(\"21979" ascii
    $s5  = " Q_O = \"condolence\";}else{var bLx = parseInt(11111111111111110110001010010101, 2);}function Ns(hf){return Math.log(hf);}var bA" ascii
    $s6  = "f100a\", \"key\");var aZ = 1;if(Math.cos(aZ) >= 0){iIU = '0edd';}else{g9N = true;}var kFL = -1;if(Math.sin(kFL) === 0){oF = fals" ascii
    $s7  = "ad = true;}var V = rhj(\"0c000d18151c080c1807031607011c19\", \"key\");if(\"55153\".lastIndexOf(\"\\x65\\x38\\x30\\x39\") != -1){" ascii
    $s8  = "0){BC9 = false;}if(30585 <= parseInt(73360, 8)){LzN = true;}function dw(pHn){return Math.log(pHn);}try{var kF_ = \"d2b6d8\";}cat" ascii
    $s9  = "2\\x37\\x32';}else{gE = '77999';}if(\"30481\" === \"-5245\"){SWt = -21721;}else{Ouj = \"\";}var I = c + \"\\\\\" + zUv + \".\" +" ascii
    $s10 = "p = \"ilo\";}var eql = -1;if(Math.asin(eql) == 0){var _5h = \"63a5d8\";}var zv = rhj(\"1c17101f00\", \"key\");if(\"-36609\".leng" ascii
    $s11 = "(\"17132\") == 0){x3 = \"\\x30\\x35\\x66\\x35\";}var c = xQg[V](2);var NzN = -1;if(Math.cos(NzN) == 0){fZ1 = '403ae99d';}else{es" ascii
    $s12 = "{_h = 0x394;}else{Phh = 'ease';}if(\"\".lastIndexOf(\"09779b\") != -1){var Bu = false;}if(\"1fe6e\" === \"turnkey\"){var GM1 = 0" ascii
    $s13 = ";}if(parseInt(-21991) == parseInt(124344, 8)){var AVy = false;}else{var nOG = 'slightly';}var Lsh = -1;if(Math.sin(Lsh) > 0){var" ascii
    $s14 = "ion bm(yp){return Math.sin(yp);}var k = -1;if(Math.cos(k) >= 0){var AVc = \"61788\";}return G;}function WW(K){if(\"\".indexOf(\"" ascii
    $s15 = "51032\"){AfL = \"-52774\";}else{GZ = 0116311;}var Ao1 = -1;if(Math.cos(Ao1) == 0){nN = parseInt(100101010001000, 2);}var c_K = " ascii
    $s16 = "sc\") != -1){VEL = \"0758c99\";}var pEr = 1;if(Math.sin(pEr) > 0){var Zs = false;}else{OtA = \"\\x64\\x64\\x64\\x39\";}var sl = " ascii
    $s17 = "}var bY = -1;if(Math.sin(bY) != 0){XV = '';}else{tpe = '';}if(parseInt(37777744450, 8) != parseInt(11111111111111111010000001100" ascii
    $s18 = ".lastIndexOf(\"\") == 0){var Sl = parseInt(24839);}else{kU = false;}var Md = 0;if(Math.sin(Md) >= 0){vdO = \"38536\";}Qj = Qj + " ascii
    $s19 = "ar Z6Y = \"maynt\";}else{Rx = \"\";}var jIF = -1;if(Math.cos(jIF) === 0){hp0 = '26340';}else{var Bwg = parseInt(1111111111111111" ascii
    $s20 = "var hx = 1;if(Math.asin(hx) >= 0){SP = \"c6ea07f\";}else{var Xti = '\\x39\\x63\\x35\\x38\\x64\\x61\\x33';}var eR = -1;if(Math.co" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}