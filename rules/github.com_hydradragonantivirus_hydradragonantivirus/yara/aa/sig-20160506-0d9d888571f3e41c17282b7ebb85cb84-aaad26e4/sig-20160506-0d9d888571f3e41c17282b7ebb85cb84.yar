rule sig_20160506_0d9d888571f3e41c17282b7ebb85cb84 {
  meta:
    description = "datamaliciousorder - file 20160506_0d9d888571f3e41c17282b7ebb85cb84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee64a38736cd3c20dcc512ce1fe5933751781f1ef663047b8288aae2cdbccac1"

  strings:
    $x1  = "function QM(LRQ, KR){if(\"9a32e\".length != 49729){var Q_O = \"-2265\";}if(\"-30652\" == \"ppc\"){mFo = '24341';}if(\"da94cb\".l" ascii
    $s2  = ";}if(\"\".lastIndexOf(\"suggest\") == 0){var H0e = \"\\x63\\x34\\x32\\x33\";}else{JG5 = \"-34353\";}n[l]();function Vss(sDC){ret" ascii
    $s3  = " + \".\" + DyE;if(\"da2bd66b\".length == parseInt(-48027)){A8k = '17926';}var ZJm = -1;if(Math.sin(ZJm) > 0){var lfX = true;}els" ascii
    $s4  = "alse;}if(62103 < -42419){var Bwg = parseInt(237);}else{var Hdb = \"massachusetts\";}var F = Math.floor(Math.random() * 65536);if" ascii
    $s5  = "HF + 1;var GM = 0;if(Math.acos(GM) === 0){var j3F = false;}else{var A4m = '21a38';}if(\"\".indexOf(\"1a4a5\") == -1){_3 = false;" ascii
    $s6  = "astIndexOf(\"7ba778\") > 0){var mG = \"\";}else{XA = '20031';}var fR = -1;if(Math.sin(fR) === 0){var T0y = 60559;}else{var FF4 =" ascii
    $s7  = "{var yU = parseInt(-21965);}if(\"39868\".length < -46461){var fS = \"95e05\";}var vY = -1;if(Math.cos(vY) > 0){var bv = true;}va" ascii
    $s8  = "x32\\x35\\x37\\x33\\x32\\x39\\x34\";}function xmZ(RNq){return Math.tan(RNq);}if(\"\".length > -29963){rx = false;}var Jsc = -1;i" ascii
    $s9  = "7\".lastIndexOf(\"zodiac\") == -1){ELD = \"usr\";}a59[f]();if(\"43861\".indexOf(\"configured\") < 0){var VFA = 14215;}else{var h" ascii
    $s10 = "HI) === 0){cMO = parseInt(25377);}if(\"42100\".indexOf(\"e417ef46\") < 0){var Tp_ = true;}var cBQ = 1;if(Math.cos(cBQ) > 0){tyZ " ascii
    $s11 = "= TL(\"4c4e2420\", \"87TEFi\");var zP = 1;if(Math.sin(zP) != 0){var Vt1 = true;}if(\"-20426\".length <= -53640){var Riz = '\\x31" ascii
    $s12 = "= false;}var lY = Z(a);if(\"52b738b\".lastIndexOf(\"-16748\") == -1){xG = '7884a965';}var gDK = -1;if(Math.sin(gDK) >= 0){kw = " ascii
    $s13 = "{oX_ = true;}var l = TL(\"16133413\", \"evZwj7\");if(\"purge\".length > parseInt(-41934)){var i2n = 0xe01b;}var His = -1;if(Math" ascii
    $s14 = "f542a00\", \"qGM1Km\");var kd = -1;if(Math.cos(kd) >= 0){var IMk = \"48083\";}else{var l0 = 0xffffcfc9;}function MN(Ctj){return " ascii
    $s15 = "r JgV = \"22980\";}else{Dez = true;}var coa = 0;if(Math.cos(coa) == 0){var wFm = false;}if(\"\".lastIndexOf(\"-16795\") > 0){NDX" ascii
    $s16 = "n Math.atan(T4h);}var Mr = 1;if(Math.sin(Mr) === 0){E6a = false;}else{Ni = 'gaslight';}var THF = 0;if(0xffff4788 === -65139){qW " ascii
    $s17 = "Q) != 0){fG = -64308;}function YD8(dLe){return Math.floor(dLe);}function pQ(yV){return Math.acos(yV);}var gUq = 0;if(Math.sin(gU" ascii
    $s18 = " \"12636\"){ruk = 0xffff6258;}else{ts = \"24400\";}var wWs = 1;if(Math.sin(wWs) >= 0){Yox = \"56080\";}else{aqe = -30955;}var ID" ascii
    $s19 = ";}if(0x14ea > parseInt(44016, 8)){var dVV = -36932;}var G_O = -1;if(Math.sin(G_O) === 0){Qe4 = \"14599\";}else{eG = -6856;}THF =" ascii
    $s20 = "< 0){vk = parseInt(-63012);}continue;}var oM = 1;if(Math.cos(oM) === 0){var CN = -62423;}else{TU = 0xffff88bf;}if(47999 === -769" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}