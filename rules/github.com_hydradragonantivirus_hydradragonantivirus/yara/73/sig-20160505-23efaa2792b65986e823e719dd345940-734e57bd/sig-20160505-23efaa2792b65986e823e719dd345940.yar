rule sig_20160505_23efaa2792b65986e823e719dd345940 {
  meta:
    description = "datamaliciousorder - file 20160505_23efaa2792b65986e823e719dd345940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46a6b52035535951c35ac8854bdaeee423b5c8b7f3b799e27961e0b2f6ee3e84"

  strings:
    $x1  = "function zE(eep, nbC){function vE(LCn){return Math.floor(LCn);}if(\"-59772\".indexOf(\"c3129\") < 0){Ekg = 9107;}else{B = \"-201" ascii
    $s2  = "astIndexOf(\"\\x62\\x31\\x35\\x39\") == 0){ho = 49737;}function bK(jJ){return Math.log(jJ);}if(\"\".indexOf(\"\\x62\\x37\\x62\\x" ascii
    $s3  = "tion OFW(vIX){return Math.log(vIX);}if(\"f2e84\".length <= parseInt(51105, 8)){var iHE = 'overran';}if(parseInt(137721, 8) == pa" ascii
    $s4  = "89';}if(\"\".length <= parseInt(-35024)){BK = 8697;}else{K7 = '';}var _u = -1;if(Math.sin(_u) > 0){Kp = 'identifier';}else{var b" ascii
    $s5  = "nealogy\".lastIndexOf(\"-50699\") != -1){var Ag = 60417;}else{me = true;}if(\"-38124\".indexOf(\"26932\") == -1){var uv0 = false" ascii
    $s6  = "r h = vIj[0];var K = -1;if(Math.sin(K) == 0){var uGD = \"51460\";}else{var vez = parseInt(11111111111111110000111000011001, 2);}" ascii
    $s7  = "O5 = true;}O = O + 1;if(\"-18713\".lastIndexOf(\"\") != -1){gE = '09a8a8';}else{var ZyF = parseInt(37777671772, 8);}if(\"\".last" ascii
    $s8  = "\\x31\\x37\\x33\";}function vI(Nrw){return Math.sqrt(Nrw);}var kI = -1;if(Math.sin(kI) === 0){XRh = parseInt(19449);}var CMo = z" ascii
    $s9  = "TL) >= 0){mq = true;}var CYD = -1;if(Math.sin(CYD) == 0){var RTs = '\\x31\\x66\\x63\\x33\\x66';}function ad(mT){return Math.cos(" ascii
    $s10 = "if(Math.cos(XG) === 0){fI = \"e0afd7d\";}if(\"-58005\".indexOf(\"9248a9\") == -1){var Ea = 0xf1eb;}else{var c0 = 'f8b1611e';}var" ascii
    $s11 = "(\"\\x37\\x38\\x63\\x37\\x66\\x37\\x32\".lastIndexOf(\"\") == -1){DVF = true;}function UGH(Mi){return Math.sin(Mi);}var Zg = \"" ascii
    $s12 = "30\";if(GF_ != mw){wpO = true;}if(\"60932\" != \"-2041\"){hQ = 'inverse';}else{var tY = 037777713250;}var VR = -1;if(Math.sin(VR" ascii
    $s13 = "MEb = 48825;}if(\"occur\".indexOf(\"\") != -1){var sph = true;}else{var DTw = 'astern';}if(n == zE(\"263f\", \"key\")){if(\"talk" ascii
    $s14 = "8';}var F = zE(\"2c202d\", \"key\");var GjV = -1;if(Math.asin(GjV) == 0){var FR = false;}if(\"138fe\".length == parseInt(-33245)" ascii
    $s15 = ".\" + CB;var oub = 1;if(Math.cos(oub) == 0){var xPL = 0xffff27f1;}function hxE(DCZ){return Math.cos(DCZ);}var gd = \"aggregate\"" ascii
    $s16 = " = -1;if(Math.asin(jRQ) >= 0){cUq = \"0b78\";}else{c = parseInt(1111101101010110, 2);}function ACt(Udi){return Math.tan(Udi);}va" ascii
    $s17 = "9 === parseInt(37777645763, 8)){var xZ = false;}else{iRN = true;}var iB = -1;if(Math.sin(iB) === 0){var vu = parseInt(35094);}Zg" ascii
    $s18 = "734471;}var GQ4 = 0;if(Math.acos(GQ4) == 0){Qa5 = -54216;}var TJ = 0;if(Math.cos(TJ) != 0){wJ = \"\\x33\\x66\\x32\\x61\\x65\\x62" ascii
    $s19 = "x61\\x30\\x39\\x33\\x30\\x38\\x36\") != -1){var NBx = true;}var Kb = 1;if(Math.sin(Kb) != 0){var jl = parseInt(-38823);}else{var" ascii
    $s20 = "\");var AZ = -1;if(Math.cos(AZ) === 0){var MxU = 'defa7';}else{var R2 = false;}var gC = 0;if(Math.asin(gC) == 0){zY = '58668';}e" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}