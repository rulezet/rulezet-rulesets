rule sig_20160506_ae20c82443f1855edecbb0c4d59366ae {
  meta:
    description = "datamaliciousorder - file 20160506_ae20c82443f1855edecbb0c4d59366ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59335f4ef0250e1cd57b86628372e3aacec012ae715e1fd2299896977eb4712c"

  strings:
    $s1  = "function OH(SOc, TtO){var HM6 = 0;if(Math.cos(HM6) >= 0){var A = true;}var tRo = -1;if(Math.sin(tRo) != 0){pU = \"-12875\";}else" ascii
    $s2  = "49){var AR = \"3971\";}var B = z + \"\\\\\" + D + \".\" + bhB;var HJ0 = 0;if(Math.cos(HJ0) > 0){var LxS = \"jowl\";}else{var dO " ascii
    $s3  = "Math.floor(fJy);}var G4r = -1;if(Math.sin(G4r) == 0){Nl = false;}if(\"0d761\".length >= -56578){qxr = true;}if(-16584 === -13194" ascii
    $s4  = "\\x34\") != -1){vzu = false;}var O = zO[3];var NAd = 0;if(Math.cos(NAd) >= 0){var dzs = true;}else{_Hz = false;}if(\"\\x35\\x33" ascii
    $s5  = ", \"P16qQFI\");function DGX(JAw){return Math.sin(JAw);}if(\"\\x65\\x32\\x38\\x62\".length >= -11893){var ROY = 0xffff94bf;}try{O" ascii
    $s6  = "und\".length < 43705){fq = 0xffff62fd;}var fY = -1;if(Math.cos(fY) === 0){var Hld = true;}else{e6 = true;}var uUr = \"7771\";var" ascii
    $s7  = "eturn Math.atan(bu);}var k2H = -1;if(Math.cos(k2H) == 0){var wRR = \"\";}var Wn = 0;if(Math.asin(Wn) >= 0){E_ = \"resound\";}els" ascii
    $s8  = "r SQj = -1;if(Math.sin(SQj) > 0){var fkk = false;}var od = uK(\"04193c5c0066431107285918201d\", \"ijD1lTm\");var Sbl = -1;if(Mat" ascii
    $s9  = "h.cos(X2u);}if(GLf == 0){var gg = -1;if(Math.sin(gg) >= 0){pg5 = '88c4';}else{var nn = parseInt(54733);}function lZ(fJy){return " ascii
    $s10 = "{var S8E = true;}function jR4(Cp){return Math.tan(Cp);}var D = Mk_();var XcD = -1;if(Math.asin(XcD) >= 0){var iD = '29175';}else" ascii
    $s11 = " 0;if(Math.cos(Xa) === 0){SH = -26330;}if(-599 === 6729){var UiQ = true;}if(\"relentless\".indexOf(\"-38352\") == -1){var VU = '" ascii
    $s12 = "= \"\";}else{rC = true;}if(parseInt(-64103) >= 0147260){EzT = '-18269';}else{var Fr = true;}Z[xtu]();var bLS = -1;if(Math.sin(bL" ascii
    $s13 = ";}var NIb = -1;if(Math.asin(NIb) >= 0){var aHG = 'competitions';}if(\"10225\".length > parseInt(-58993)){VE = \"c76b6ac\";}else{" ascii
    $s14 = " -1;if(Math.cos(_q) === 0){var cj = \"\\x32\\x35\\x33\\x31\\x35\\x64\";}var CcW = 0;if(Math.acos(CcW) != 0){var Qm = '';}else{va" ascii
    $s15 = "5071d21\", \"0ihnDN2E\");if(\"a43cf08f\".lastIndexOf(\"\") > 0){Ck = -20576;}else{YxX = '7d5e9e';}function Cv(y6P){return Math.c" ascii
    $s16 = " bI = 1;if(Math.cos(bI) == 0){FZy = 0xffffc35b;}if(19165 >= 57685){var MX = true;}var mj = -1;if(Math.acos(mj) == 0){Tz = '\\x61" ascii
    $s17 = "se{rh = true;}var cIF = -1;if(Math.cos(cIF) === 0){var hr = 0x69e3;}var Fu = 1;if(Math.asin(Fu) != 0){var Rc = -16816;}function " ascii
    $s18 = ", \"WlJk8RF\");if(\"0a30984c\".lastIndexOf(\"f5e29892\") != -1){var pP = \"\";}var nZx = 0;if(Math.cos(nZx) > 0){Nnp = \"44739\"" ascii
    $s19 = "M6 = false;}if(\"30998\" === \"obsession\"){vBe = 40405;}else{var fxQ = 'd597';}if(\"2132\".indexOf(\"\\x31\\x31\\x61\\x30\\x36" ascii
    $s20 = " = false;}if(037777723172 != -22266){var i0 = false;}var nZ = 1;if(Math.cos(nZ) === 0){var U = 65519;}var hd1 = \"\";var C8 = 1;" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}