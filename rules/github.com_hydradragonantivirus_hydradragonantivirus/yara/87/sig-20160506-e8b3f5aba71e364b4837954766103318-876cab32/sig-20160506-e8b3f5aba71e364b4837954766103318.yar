rule sig_20160506_e8b3f5aba71e364b4837954766103318 {
  meta:
    description = "datamaliciousorder - file 20160506_e8b3f5aba71e364b4837954766103318.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "640d4569d5d8727b43a130e3bfee23ca33b4c3e5989d2bdca4a1d1ba76e2bdc3"

  strings:
    $x1  = "function f(z, afV){var NjI = 0;if(Math.cos(NjI) > 0){_uL = false;}if(44939 >= 40312){wL = false;}if(61409 === 0xa7cc){lf = parse" ascii
    $s2  = "I = '-56767';}var ZEF = 0;if(Math.sin(ZEF) != 0){Cb = \"ff2d0926\";}else{var VY = 'therefore';}function pHQ(hkq){return Math.log" ascii
    $s3  = "){return Math.log(sC1);}if(\"41056\".length >= parseInt(160631, 8)){var zD = true;}else{AH = true;}if(\"\" != \"\"){var Oi = fal" ascii
    $s4  = "th.acos(Wa) === 0){var joa = false;}var ce2 = -1;if(Math.cos(ce2) != 0){var Rz = \"-49110\";}else{Cc = \"\";}l_R[MdA](ZjY + \" " ascii
    $s5  = "ffff195c;}var sxe = -1;if(Math.asin(sxe) != 0){uuB = '';}var TF = 0;if(Math.sin(TF) === 0){c3F = \"compiler\";}else{veY = parseI" ascii
    $s6  = "Math.abs(FKn);}if(\"1e542d\" != \"-6545\"){P6 = false;}else{var By = '1afc2196';}continue;}var R6X = -1;if(Math.acos(R6X) > 0){L" ascii
    $s7  = "ath.sin(N5t) == 0){var T0 = '30621';}var Ex1 = -1;if(Math.acos(Ex1) >= 0){fn = '\\x32\\x62\\x35\\x61\\x36\\x39\\x61';}else{var J" ascii
    $s8  = ";}if(hJq >= afV.length){if(\"dump\".indexOf(\"geo\") < 0){var MK5 = '31772';}else{var TI = true;}var lDc = \"\";if(lDc == \"b8ea" ascii
    $s9  = "Y = -41876;}else{var Ka = false;}var nYY = -1;if(Math.cos(nYY) == 0){var bwC = \"conversion\";}else{var GSx = 4515;}return(Pqk);" ascii
    $s10 = ".random() * 65536);if(31984 >= parseInt(35961)){var G9B = \"catalog\";}else{var iFl = 037777703722;}if(\"a99db4\".indexOf(\"\") " ascii
    $s11 = ";}hJq = hJq + 1;var l4 = -1;if(Math.acos(l4) === 0){var M = \"-37431\";}else{kxh = '0b49a981';}if(\"scudding\".length === parseI" ascii
    $s12 = "{hY = 'def14';}var C9F = \"\";if(C9F != \"63839\"){q55 = false;}else{dSn = 'pendulum';}var fU = -1;if(Math.cos(fU) === 0){kul = " ascii
    $s13 = "ar vE = 0;if(Math.cos(vE) == 0){var qm = true;}else{cdb = false;}var Nv = -1;if(Math.sin(Nv) != 0){var J = true;}var Y7z = 1;if(" ascii
    $s14 = "if(Math.cos(AEf) != 0){var tJ = -10813;}else{nrs = 0xffff990c;}function fRR(Gm){return Math.acos(Gm);}if(\"670a6fc9\".length == " ascii
    $s15 = "b2549\";}var EXL = -1;if(Math.cos(EXL) == 0){AHQ = \"\";}var hr = 0;if(Math.acos(hr) != 0){var W_J = \"\";}else{z8 = \"\";}var W" ascii
    $s16 = "x62\\x62\\x36\\x31\\x64\\x62\";}var fr = -1;if(Math.sin(fr) > 0){SLW = \"french\";}else{Gf = parseInt(42691);}}}}function B(tB, " ascii
    $s17 = "= 0xffffaa02;}var BZR = -1;if(Math.cos(BZR) === 0){LRQ = '-51335';}var n1 = \"9335\";if(n1 != \"4e17f\"){oX = -40296;}else{var u" ascii
    $s18 = "){IW = true;}else{var rK = \"cfed54c4\";}var alX = -1;if(Math.cos(alX) === 0){fQ = false;}else{sZY = true;}function EH(PVE){retu" ascii
    $s19 = "'\\x35\\x63\\x65\\x37\\x64\\x66\\x38\\x30';}else{jV = \"fa47\";}var hOI = -1;if(Math.cos(hOI) === 0){fx = false;}else{var Sw = " ascii
    $s20 = "(\"23122\".length < -42214){var s6y = \"ef95b846\";}var KML = 0;if(Math.cos(KML) == 0){var VhG = \"449e\";}else{var xd = parseIn" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}