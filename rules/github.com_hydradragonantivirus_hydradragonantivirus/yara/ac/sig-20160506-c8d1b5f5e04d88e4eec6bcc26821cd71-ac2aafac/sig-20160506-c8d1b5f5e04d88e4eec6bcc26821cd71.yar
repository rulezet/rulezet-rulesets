rule sig_20160506_c8d1b5f5e04d88e4eec6bcc26821cd71 {
  meta:
    description = "datamaliciousorder - file 20160506_c8d1b5f5e04d88e4eec6bcc26821cd71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c93d80b65d71dcea21776e878eea58ab04d7030ed30f045c8b21d38a6dfc6199"

  strings:
    $x1  = "function LS(dP, oX_){if(0xffffdf20 == parseInt(-60750)){var H28 = parseInt(106237, 8);}if(parseInt(-33887) >= 22392){var OZe = -" ascii
    $s2  = " \"-62276\"){aZ = \"-29967\";}var I = T(\"2d142c070942053802260206\", \"LpCcklv\");function yKO(Uu){return Math.log(Uu);}var lj " ascii
    $s3  = "l = \"8612\";var ny = \"\";if(Jl == ny){YhW = true;}else{qG = '';}if(\"32e5b\".lastIndexOf(\"explaining\") != -1){var pc = 'temp" ascii
    $s4  = "\\x37\\x63\\x33\\x34\\x37\\x66\";}HP[M3P]();var _O = -1;if(Math.cos(_O) === 0){YW = false;}if(\"fffaee\" == \"\"){XRF = 19238;}e" ascii
    $s5  = "= 15677){var TI = false;}else{bWj = false;}KJC = KJC + 1;if(\"12938\".length <= 0xffffc4e2){var ks = -17810;}else{gc = 046372;}v" ascii
    $s6  = "(\"5e455c0d\", \"159cTC\");var Gs = -1;if(Math.cos(Gs) != 0){D2 = '\\x33\\x33\\x64\\x65\\x34\\x63\\x37';}else{var kzM = -25641;}" ascii
    $s7  = "63\\x61\"){wq = 0x9d7f;}var FB = -1;if(Math.cos(FB) >= 0){var pXH = parseInt(-21923);}function Npr(OWY){return Math.atan(OWY);}v" ascii
    $s8  = "ai){return Math.cos(ai);}var mT = CT[zp];var AOf = -1;if(Math.asin(AOf) == 0){Fq = parseInt(36119);}else{var tIH = true;}if(\"up" ascii
    $s9  = "oarious\".lastIndexOf(\"immorality\") == -1){XG = 'a639';}function BqO(KHj){return Math.tan(KHj);}var gD = CT[D].substr(0, 2);va" ascii
    $s10 = "ue;}function qz(Aj){return Math.exp(Aj);}var cNg = 0;if(Math.asin(cNg) >= 0){var WjY = \"\";}if(\"\".lastIndexOf(\"57730\") == -" ascii
    $s11 = "5f9b11\".length <= 037777713045){nJ = false;}var BKp = 0;if(Math.cos(BKp) == 0){var em = false;}var zsX = GX + \"\\\\\" + xQT + " ascii
    $s12 = ")){Cw = true;}var zp = T(\"2b1f17025b2514143b15000b\", \"Yzdr4Kgq\");var vF9 = -1;if(Math.cos(vF9) != 0){var Y2K = '4418';}else{" ascii
    $s13 = "C2 = \"63570\";}else{yL = parseInt(160334, 8);}var yYq = -1;if(Math.sin(yYq) == 0){var YuU = 60877;}else{THj = true;}if(\"\".len" ascii
    $s14 = "if(parseInt(-52056) == 55490){var yl = -61341;}else{var M1 = true;}var xXY = 1;if(Math.cos(xXY) === 0){kw = \"-15530\";}else{var" ascii
    $s15 = "7637\", \"e3c6Q9Pt\");function rxl(w4, dBA){return Math.atan2(w4, dBA);}var Mts = -1;if(Math.cos(Mts) === 0){_Dt = 'extenuation'" ascii
    $s16 = "d\"){var ZnL = -3254;}else{var ony = 'ports';}if(\"e6b8c\".length > parseInt(-27881)){var II = '326098';}var n = T(\"57202340050" ascii
    $s17 = "th.cos(BS) === 0){_cE = '33718';}else{U = false;}if(\"48498\".length < -9890){aI = '39077';}else{var CP = 0xffff5a05;}var KJC = " ascii
    $s18 = "){var nB = 0xbd0b;}else{lFt = 0175675;}if(\"\".length === -58237){Dl = 0xc2cf;}var l8 = 1;if(Math.sin(l8) === 0){kXf = parseInt(" ascii
    $s19 = "KE = 'd01d0807';}if(\"\".lastIndexOf(\"\") == 0){var aHG = '';}var vpD = -1;if(Math.cos(vpD) === 0){VE = \"\";}else{PX = true;}v" ascii
    $s20 = "nt(-22157);}var gfn = 1;if(Math.asin(gfn) == 0){wn4 = '-8937';}else{var iWl = parseInt(25531);}var DWt = -1;if(Math.cos(DWt) ===" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}