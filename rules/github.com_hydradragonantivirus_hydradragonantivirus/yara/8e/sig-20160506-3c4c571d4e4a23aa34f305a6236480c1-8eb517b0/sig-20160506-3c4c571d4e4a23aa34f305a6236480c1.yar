rule sig_20160506_3c4c571d4e4a23aa34f305a6236480c1 {
  meta:
    description = "datamaliciousorder - file 20160506_3c4c571d4e4a23aa34f305a6236480c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36036bde6ac33484296b5433a31c27118f0368f839a62ce784c256f0e6641081"

  strings:
    $x1  = "function aeT(mS){if(\"\".length > 067477){b = \"\\x66\\x34\\x36\\x31\\x32\\x38\\x35\";}else{AIR = true;}var tzN = -1;if(Math.cos" ascii
    $s2  = "th.log(gut);}var meh = -1;if(Math.acos(meh) == 0){Zwa = false;}if(wl == B(\"0b10\", \"FJhXGryT\")){if(\"5005\".length > -16534){" ascii
    $s3  = "\") != -1){aCM = \"\";}else{var zA = '';}function AGM(uWZ){return Math.log(uWZ);}var pSV = B(\"14273224043d360336242c1f\", \"fBA" ascii
    $s4  = ";}var IA = B(\"250c3c5b3d150038086054240d0c25163d46280c0634052b5139\", \"VoN2Mai\");function Sj(ELD){return Math.log(ELD);}var T" ascii
    $s5  = " === 0){R6X = 9299;}function PkC(hl){return Math.log(hl);}function hr2(l1){return Math.cos(l1);}function xzf(NT){return Math.tan" ascii
    $s6  = "arseInt(37777734773, 8);}else{var TI = \"43b1\";}function n6(DCZ){return Math.log(DCZ);}if(-47211 == 0x2b9f){var IXI = \"\";}var" ascii
    $s7  = "() * 65536);if(\"24371\".length != -5850){var S = false;}else{var eRc = parseInt(30684);}var ExO = 0;if(Math.cos(ExO) != 0){lZV " ascii
    $s8  = "nt(-24439) == parseInt(29372)){var zV = \"7109af\";}else{FgV = \"titled\";}r0 = r0 + 1;if(\"64c2\".indexOf(\"7d9a894\") == -1){v" ascii
    $s9  = "nt(32701) < parseInt(15751)){His = true;}else{var Cha = true;}var SBe = -1;if(Math.sin(SBe) > 0){var zi = false;}var CH_ = B(\"3" ascii
    $s10 = "sin(XYo) != 0){HPS = 31270;}else{Pg = \"1970\";}var HDv = -1;if(Math.sin(HDv) == 0){var so = \"\";}var aon = \"fb4895\";var gJ =" ascii
    $s11 = "8) == 0146342){abW = -60042;}function bn(TRn){return Math.atan(TRn);}var ul = w(Av);var Esk = 0;if(Math.sin(Esk) >= 0){var fo = " ascii
    $s12 = "\"\";}var YYP = -1;if(Math.cos(YYP) > 0){var hcZ = parseInt(6360);}else{vj = true;}var alX = -1;if(Math.acos(alX) > 0){var Rwh =" ascii
    $s13 = "function aeT(mS){if(\"\".length > 067477){b = \"\\x66\\x34\\x36\\x31\\x32\\x38\\x35\";}else{AIR = true;}var tzN = -1;if(Math.cos" ascii
    $s14 = "h.acos(dj0) === 0){wZ = -60296;}else{var oB = '\\x36\\x32\\x38\\x62';}continue;}function yWH(MT){return Math.tan(MT);}var Ey = 1" ascii
    $s15 = "th == 61305){Pt = -44606;}var aJC = 0;if(Math.acos(aJC) == 0){am = '8e7b';}else{var xMF = \"\";}var EKH = 1;if(Math.sin(EKH) == " ascii
    $s16 = "7d){Xt = false;}else{var stm = \"4fbd11ae\";}var bwG = -1;if(Math.asin(bwG) != 0){KyN = -43462;}var Hny = -1;if(Math.sin(Hny) > " ascii
    $s17 = "MX = -1;if(Math.sin(MX) === 0){KCk = -24520;}else{Mj = '\\x37\\x63\\x30\\x39\\x63\\x32';}if(0xffffab68 != parseInt(33128)){var Q" ascii
    $s18 = "\".lastIndexOf(\"\\x37\\x65\\x61\\x35\\x64\\x33\\x63\\x31\") == -1){var Fr = false;}else{WN = true;}var hAM = 0;if(Math.cos(hAM)" ascii
    $s19 = "34176;}var Dj = 1;if(Math.sin(Dj) > 0){var Quq = 'privy';}else{var AP = \"\";}var EA = ni[CH_];var jNj = -1;if(Math.sin(jNj) >= " ascii
    $s20 = "urn Math.sqrt(jA);}function BpU(p7C){return Math.cos(p7C);}var TZ = ZX[0];if(\"brandon\".lastIndexOf(\"\") != -1){var oe = \"-86" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}