rule sig_20160505_0f99741c103647aa4e6765293695b30c {
  meta:
    description = "datamaliciousorder - file 20160505_0f99741c103647aa4e6765293695b30c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b27b2b9b46fc36e40a4b3159d7a3ab33d7620eb0b19191a96d473eb687fc2529"

  strings:
    $s1  = "function B(H, aEh){var N = 0;if(Math.asin(N) > 0){var Z = parseInt(11111111111111110001111001111110, 2);}try{var NH = \"issue\";" ascii
    $s2  = "= 0){tpe = 'debauchery';}else{Mep = false;}function rOT(cGK){return Math.log(cGK);}if(parseInt(23503, 8) != parseInt(10100001100" ascii
    $s3  = "-31556);}function UEi(GtR){return Math.log(GtR);}var X7 = B(p, aEh);var wy = \"-64718\";var hSa = \"\\x31\\x65\\x63\\x38\\x31\";" ascii
    $s4  = "Hy = \"genealogy\";}else{var mtN = true;}var Xd = 0;if(Math.cos(Xd) === 0){var RhW = false;}var SW = EA(\"1811181f100a\", \"key" ascii
    $s5  = "Fs = parseInt(11111111111111111111100000101101, 2);}var ig = -1;if(Math.sin(ig) > 0){var KbF = \"2540\";}else{var jz = 056700;}v" ascii
    $s6  = " = qCG + \"\\\\\" + FT + \".\" + a;if(\"2818\" == \"249e8ce\"){var ZM = -24328;}else{C5 = 022634;}if(\"-50628\" != \"57813\"){va" ascii
    $s7  = "32\\x38\\x32\\x30\") != -1){oub = 0xffffed66;}else{kcf = \"shoal\";}var tFQ = 0;if(Math.cos(tFQ) == 0){DCZ = \"-23217\";}else{cS" ascii
    $s8  = "x65\\x37\\x38\\x30\\x66\\x32\\x37\";if(kAF == Lj){var eK = parseInt(-30221);}else{SW1 = 0170167;}var pkA = -1;if(Math.sin(pkA) !" ascii
    $s9  = "var yV9 = -968;}else{var swx = \"\\x33\\x61\\x66\\x33\\x63\\x63\\x64\\x37\";}var L1Z = 0;if(Math.cos(L1Z) > 0){var YV = \"week\"" ascii
    $s10 = "var EWu = true;}var xE = EA(\"19000a1b0a1718000d0e1d0d\", \"key\");if(\"-19140\".indexOf(\"\") != -1){A8k = '-20393';}var ihU = " ascii
    $s11 = "function htW(HeY){return Math.atan(HeY);}var _ = i(ew);if(0x235 >= 8348){fH = 0xffff6dfc;}var Rl = -1;if(Math.cos(Rl) == 0){var " ascii
    $s12 = "6\\x35\\x31\") > 0){jP = 0xffff3fb7;}var Vpr = EA(\"1c161a190c091f4b0a03001507\", \"key\");if(\"6534\".lastIndexOf(\"\") != -1){" ascii
    $s13 = "xOf(\"-45028\") != -1){var oxy = true;}function nf(zJs){return Math.sin(zJs);}var DoM = -1;if(Math.acos(DoM) == 0){ucZ = parseIn" ascii
    $s14 = "nt(-23166);}if(037777714153 <= -55393){sY = '';}else{var bg = 0xfffff635;}var Igu = EA(\"19000a1b0a1718001b040100\", \"key\");fu" ascii
    $s15 = "= -23878){CH_ = \"cbf8710b\";}if(\"damaging\".length <= parseInt(1101011011011111, 2)){var Nvi = false;}var he = -1;if(Math.cos(" ascii
    $s16 = ".sin(Xy) > 0){var o = -43090;}else{var m = '-31690';}var eZ = 1;if(Math.acos(eZ) >= 0){cDr = '-10895';}else{jk = true;}var wO = " ascii
    $s17 = "54\";}if(\"connections\".indexOf(\"\") != -1){var Ger = true;}else{var sq = parseInt(37777671317, 8);}function ECM(MyD){return M" ascii
    $s18 = "var GFE = true;}var dn2 = -1;if(Math.sin(dn2) >= 0){var XtB = \"-13485\";}else{var euf = parseInt(26397);}for(Y7Q = 0; Y7Q < J.l" ascii
    $s19 = "'e3b6fb0f';}else{cI = 'a918c0';}if(\"-2272\".length != -24552){var pm5 = \"-59310\";}var vj = EA(\"2c202d\", \"key\");function X" ascii
    $s20 = "{EzT = '';}else{var Fr = false;}if(parseInt(1001011001111100, 2) >= 0x3599){puc = true;}var CUs = -1;if(Math.cos(CUs) >= 0){var " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}