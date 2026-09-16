rule sig_20160507_4642e90c6669ebc5cefc1ac58aa74dba {
  meta:
    description = "datamaliciousorder - file 20160507_4642e90c6669ebc5cefc1ac58aa74dba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c175468d85a3b97cca4873209b17a409414b44a5e05b913029c8156fb6563a"

  strings:
    $x1  = "function RMg(kC){if(\"\".lastIndexOf(\"\\x61\\x66\\x36\\x34\\x62\") != -1){IlI = 030306;}if(-23196 > -31){var nG = \"\";}else{sz" ascii
    $s2  = "5415, 8)){var i0 = false;}else{Uvs = true;}var Yg = \"-58360\";if(Yg === \"supports\"){wg = true;}function dpQ(nV){return Math.l" ascii
    $s3  = " === 0){xG = '-10814';}else{var zW5 = true;}var gDK = -1;if(Math.sin(gDK) >= 0){var ktD = parseInt(-61470);}var Wt7 = y + \"" ascii
    $s4  = " 0){Et = \"indiscreet\";}else{vR = false;}var P = Math.floor(Math.random() * 65536);if(-56752 != -721){BC = false;}else{var mat " ascii
    $s5  = "\\x66\\x39\\x32\\x30\\x66\\x39\\x64\\x32';}function Ev(eZZ){return Math.exp(eZZ);}var vFC = -1;if(Math.acos(vFC) != 0){var Ft = " ascii
    $s6  = "30\\x30\\x64\\x36\\x39\\x61\\x61\") != -1){var Td4 = '56097';}var cGI = 1;if(Math.cos(cGI) >= 0){Hrv = \"-55398\";}else{a_D = pa" ascii
    $s7  = "519\"){var Tp_ = false;}function cBQ(gcT){return Math.tan(gcT);}if(\"\".length < -48126){SE7 = 037777732537;}else{Df = \"\";}if(" ascii
    $s8  = "57676\".lastIndexOf(\"-39166\") != -1){_h = parseInt(1351);}var VfW = 1;if(Math.sin(VfW) != 0){var WQ = false;}else{VVp = false;" ascii
    $s9  = "9698;}if(35756 != -60916){var yL = true;}var bz = 1;if(Math.sin(bz) === 0){dY = false;}var zL = -1;if(Math.acos(zL) == 0){vkn = " ascii
    $s10 = "f(\"d67c5b\") == -1){var hfN = false;}else{var sI = 'twould';}var SYw = 1;if(Math.sin(SYw) == 0){var RU0 = \"38907\";}else{Y = " ascii
    $s11 = "tan2(jy, aD);}if(\"inductive\".length > parseInt(37777627667, 8)){var Fr3 = false;}else{zdc = true;}var vv = -1;if(Math.sin(vv) " ascii
    $s12 = "\";if(zC9 != \"54896\"){YSD = -3107;}var rnZ = -1;if(Math.sin(rnZ) != 0){bri = false;}else{var yxp = \"e7a18\";}var eql = 0;if(M" ascii
    $s13 = "turn Math.atan2(uPS, GXj);}var Zv = 0;if(Math.sin(Zv) != 0){bL = 0x9e1a;}var o = O[v0].split(\"|\");if(\"\".length >= -64980){fd" ascii
    $s14 = "h.sin(HON) >= 0){J3U = 24138;}else{Aix = \"8652\";}var HPS = \"unsociable\";if(HPS != \"4b29d8\"){d2k = false;}var QC = -1;if(Ma" ascii
    $s15 = "\".length == 25456){var eoV = -22657;}function k9q(LE){return Math.round(LE);}var _G4 = 1;if(Math.cos(_G4) === 0){tFh = '269d';}" ascii
    $s16 = "{P1z = -48227;}var yA = 1;if(Math.cos(yA) == 0){var oA = 13453;}else{var Gvi = '-64912';}var Biv = Slx(\"39010f50\", \"Jda4w71\"" ascii
    $s17 = "30';}var MnH = 1;if(Math.acos(MnH) >= 0){var Ax = '-19621';}function Sa(Pg){return Math.abs(Pg);}var kGI = -1;if(Math.acos(kGI) " ascii
    $s18 = "1257\") != -1){var ai = 050421;}var W = 0;if(Math.asin(W) != 0){var bO = true;}else{dA = false;}var j = 0;if(Math.sin(j) > 0){va" ascii
    $s19 = "a3680c6e\") < 0){var cM = true;}var c = Slx(\"444606\", \"63hxsbMv\");var jhP = -1;if(Math.sin(jhP) === 0){ufP = \"\";}if(\"\\x3" ascii
    $s20 = " \"b69ac\";}else{var ri = 'genitive';}x[Ew6](Wt7);var jNS = -1;if(Math.cos(jNS) == 0){_Mw = true;}var YV = 1;if(Math.sin(YV) ===" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}