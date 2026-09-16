rule sig_20160507_2fabfe4f628222e6ec1ba9414cac1de8 {
  meta:
    description = "datamaliciousorder - file 20160507_2fabfe4f628222e6ec1ba9414cac1de8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b4de2f4585a8c61fab1bc33052b9072c800452c37a67cf9da49ebb88c05a04e"

  strings:
    $s1  = "function UN(lyL){if(\"dionysus\".indexOf(\"discrimination\") > 0){var Yz = false;}else{B = true;}if(parseInt(-37859) === 0377777" ascii
    $s2  = "r Nm = 0;if(Math.asin(Nm) === 0){SkV = \"23141\";}else{S1 = parseInt(6131);}var xs5 = I(Ekq);function cGI(u){return Math.log(u);" ascii
    $s3  = "\\x66\\x66\\x62';}var DV = -1;if(Math.sin(DV) == 0){VZg = parseInt(106405, 8);}else{In = \"21a94c7\";}if(Dw[FrV] == 200){var Daq" ascii
    $s4  = "(Ekq, HLo){var Rh = -1;if(Math.acos(Rh) == 0){FA = 'bd26c6a5';}else{var WSm = -37304;}var xx = 0;if(Math.cos(xx) > 0){var ss = " ascii
    $s5  = "r sEf = false;}else{var xbL = '\\x37\\x65\\x61\\x35\\x31\\x66\\x64';}function T4h(sm){return Math.cos(sm);}var UI = -1;if(Math.s" ascii
    $s6  = ";}var cR = -1;if(Math.asin(cR) == 0){var JCr = parseInt(63589);}var Iu = -1;if(Math.sin(Iu) > 0){CiR = 0xffff95b5;}else{_H = \"4" ascii
    $s7  = "ndexOf(\"63840\") != -1){XM = true;}var BV = -1;if(Math.cos(BV) === 0){QaA = false;}if(\"prolixity\".lastIndexOf(\"\\x33\\x35\\x" ascii
    $s8  = "eInt(AKp[2]);if(\"-24350\".length >= -39283){var Q4 = false;}var swA = 0;if(Math.sin(swA) === 0){var Bo = '';}var TF = \"25563\"" ascii
    $s9  = "e\") == -1){yC = '54498';}var on = 0;if(Math.sin(on) >= 0){dRA = parseInt(160146, 8);}else{var mXD = true;}if(parseInt(53189) < " ascii
    $s10 = "2e5\".indexOf(\"-29442\") == 0){Q1q = false;}var au = -1;if(Math.sin(au) != 0){Tju = 037777756374;}var MYH = C(\"3d4b09041b163e1" ascii
    $s11 = "093\".indexOf(\"\") != -1){var nM = \"\\x31\\x62\\x61\\x66\\x66\\x37\";}function TI(Ro){return Math.sin(Ro);}A[c_K] = 1;if(\"\\x" ascii
    $s12 = " Cwn.length; uX8++){try{if(\"92ef03\".indexOf(\"accomplishing\") == 0){WK = 0xc610;}else{var LtR = false;}if(\"-38187\".length >" ascii
    $s13 = "3f02060526571b3e\", \"xJZoigL2\");var d8G = -1;if(Math.cos(d8G) != 0){slp = 'richardson';}else{LI = true;}if(-16835 <= 64430){va" ascii
    $s14 = "46\".indexOf(\"-34486\") != -1){var WC = true;}var lTq = 1;if(Math.asin(lTq) != 0){f0j = false;}var Msk = 0;if(Math.cos(Msk) != " ascii
    $s15 = "{return Math.asin(oub);}A[jd6]();var ZV = -1;if(Math.cos(ZV) >= 0){var VFR = true;}else{var hP = '32460';}var ET = -1;if(Math.as" ascii
    $s16 = "87 >= -30262){var lPo = '60345';}else{LIu = '-62121';}var sT = 1;if(Math.sin(sT) == 0){nit = '16457';}else{var j8P = parseInt(-2" ascii
    $s17 = "x31\\x31\\x37\\x30\\x30\\x31\\x37\\x62\") > 0){PX = 'd947bf06';}var N8 = -1;if(Math.sin(N8) === 0){dn = \"filing\";}else{var RU " ascii
    $s18 = "39\\x63\\x63\\x39\\x38\\x32\\x30';}if(18765 <= -2127){var Rzl = 0175764;}else{var K_j = \"20847\";}var d6C = -1;if(Math.sin(d6C)" ascii
    $s19 = " = false;}var NjP = 0;if(Math.sin(NjP) == 0){var Hqj = \"en\";}function Eq(xD){return Math.atan(xD);}A[DJk]();var joV = -1;if(Ma" ascii
    $s20 = "701';}var QM = 0;if(Math.cos(QM) === 0){xoS = false;}else{nj = '47522';}var oI = Q[tf](2);var vf = -1;if(Math.asin(vf) != 0){var" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}