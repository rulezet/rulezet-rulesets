rule sig_20160505_8fcc5ec6d1ad8eb2f2b0c45bae20ff82 {
  meta:
    description = "datamaliciousorder - file 20160505_8fcc5ec6d1ad8eb2f2b0c45bae20ff82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b58a1c26b0fcf2a041f11ea9b2f0b514b8d6dbe7e020350a96f65339f640b60"

  strings:
    $x1  = "function zsV(){var Bqa = -1;if(Math.asin(Bqa) >= 0){G = parseInt(11111111111111110010110111111001, 2);}function J(es){return Mat" ascii
    $s2  = "= 0){var T0y = -3438;}}}}function EV(HDc){function K6N(eX){return Math.log(eX);}var jy = 1;if(Math.sin(jy) === 0){Q88 = parseInt" ascii
    $s3  = "e(l2w){return Math.log(l2w);}var FV = 0;if(Math.asin(FV) >= 0){sQ = \"\\x31\\x64\\x31\\x66\\x30\\x35\\x65\";}else{Z3 = \"\";}if(" ascii
    $s4  = "Math.sin(n4);}if(parseInt(-40567) == -41690){z = false;}if(parseInt(11111111111111111000101111110000, 2) != parseInt(47767)){var" ascii
    $s5  = ", \"key\");function kZs(wM3){return Math.ceil(wM3);}var kvn = -1;if(Math.cos(kvn) != 0){n6 = \"23bc3a\";}var mo = 0;if(Math.cos(" ascii
    $s6  = "555503110d1b5f5644080005040a1f0457080a1444041d064b1c1300055b19481755\", \"key\");var mF = -1;if(Math.sin(mF) == 0){var Fr = true" ascii
    $s7  = "\", \"key\");function PX(EY2){return Math.sin(EY2);}var pw = -1;if(Math.sin(pw) != 0){var bU2 = '8519';}else{var WgL = true;}var" ascii
    $s8  = "m = true;}else{Ig = '-55765';}if(\"javascript\".indexOf(\"\") != -1){var XC = \"-39858\";}var jgo = \"\\x34\\x39\\x30\\x65\\x66" ascii
    $s9  = "else{var SI = 1;if(Math.sin(SI) > 0){Je = \"19419\";}if(\"\\x35\\x33\\x31\\x37\\x61\\x31\\x62\".indexOf(\"\") != -1){bj = 036537" ascii
    $s10 = "f(Math.acos(ZIx) >= 0){var LxS = \"-54922\";}var osT = -1;if(Math.sin(osT) > 0){VuG = \"gui\";}else{T_8 = 070771;}for(r0 = 0; r0" ascii
    $s11 = "15, 8) >= parseInt(33137)){Ljm = \"51770\";}else{Fl = 0177763;}var nI = dEV(\"19000a1b0a1718000d0e1d0d\", \"key\");var Oiw = -1;" ascii
    $s12 = "{Yz = 0xffff692c;}var pJ = -1;if(Math.asin(pJ) != 0){var Lxv = '5c738e';}else{JAV = '19550';}function tJq(iXj){return Math.sin(i" ascii
    $s13 = "= -1;if(Math.sin(ejG) == 0){var ZF = '35213';}else{var oK = '';}for(V = 0; V < OT.length; V++){try{function bL(TLH, xQx){return " ascii
    $s14 = "){var GVs = -1;if(Math.cos(GVs) === 0){var Yzc = true;}function dGd(FYZ){return Math.floor(FYZ);}if(\"9778\".length === 0xfffff1" ascii
    $s15 = "il(gzJ);}var We9 = -1;if(Math.cos(We9) == 0){var nYu = true;}var hOI = \"-4342\";if(hOI === \"3324e0\"){vH = false;}else{var Wj " ascii
    $s16 = "OT[V].split(\"|\");var en = -1;if(Math.sin(en) > 0){var qSe = \"\\x39\\x39\\x35\\x63\\x61\";}else{O7m = \"trance\";}if(parseInt(" ascii
    $s17 = "oV = -1;if(Math.acos(oV) === 0){DM8 = \"\\x36\\x30\\x33\\x61\\x36\";}else{fJy = 0xffff06bc;}var HQ0 = 0;if(Math.sin(HQ0) != 0){v" ascii
    $s18 = " HbX = false;}if(\"\\x39\\x63\\x38\\x37\\x38\\x30\".indexOf(\"-38204\") == 0){HIh = 31360;}else{var Pz = false;}var sk = -1;if(M" ascii
    $s19 = " FR = true;}var K_3 = -1;if(Math.sin(K_3) != 0){var jY = '\\x62\\x36\\x31\\x38\\x62\\x34';}else{sDa = '\\x32\\x38\\x66\\x32\\x34" ascii
    $s20 = "8x.length; r0++){var Xbv = -1;if(Math.sin(Xbv) != 0){yWa = true;}else{ILV = '853c5fcb';}function EL(wg, BU){return Math.atan2(wg" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}