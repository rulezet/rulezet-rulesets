rule sig_20160324_398e3705bb48502be315e54ad43ceb99 {
  meta:
    description = "datamaliciousorder - file 20160324_398e3705bb48502be315e54ad43ceb99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a82e0ebaac7c9b939d7e41c162c73b283a4e70d5635f926bfec295182b6cde82"

  strings:
    $s1  = "var DC = \"c\\x6cose\";function C1(tJl){var _112crap = \"s\"; return \"\" + tJl + \"\";};function pJL(A0){var _112crap = \"s\"; " ascii
    $s2  = "ar hFd = new this[NlL](),IOj = hFd[FW(sgQ) + FtM + g + U]();WScript[Y](j());var hFd = new this[d(NlL)](),yx = hFd[Jx(sgQ) + jC(F" ascii
    $s3  = "eO\\x62je\",CQ = \"\\x43re\\x61t\";var GkM = false,Bq = \"CreateObject\";var bB = function h() {return WScript[Bq](cGq + om(bQ) " ascii
    $s4  = "ion j(){return 22;};var u = 0,EE = 0;function NZc(){var hFd = new this[NlL](),SF = hFd[Z(sgQ) + FtM + g + U]();WScript[Y](j());v" ascii
    $s5  = "sdf76ags\" + 123313 * u + EE; break;}}function P() {return ((pdy == true) && (pdy == VlU)) ? 1 : f;};if (pdy && P() && VlU){func" ascii
    $s6  = "ion uq() {return bB[y + TJo + f1(Aya) + mX + eb + h0](ca + Jpw) + U0 + G + LOW + xS;}; Qe = m(); n = WScript[Bq](Qe); var POL = " ascii
    $s7  = "ion Cg(xHg){var _112crap = \"s\"; return \"\" + xHg + \"\";};var t0 = \"t\\x69on\",rw = \"po\\x73i\";function Cl0(Fv){var _112cr" ascii
    $s8  = "tM) + g + U]();var u = \"LlE\";u = wu(IOj, SF);var EE = \"Lei\";EE = wu(yx, IOj);return wu(u, EE);}var pdy = false,VlU = false;f" ascii
    $s9  = "1; while (POL){try {n[O(XZB)](O0, Js + Z0 + ZP(Gd) + jgu + nVG + Isb, false);n[j0]();v = \"Sleep\";while (n[xAB + eSb] < 4 ) {WS" ascii
    $s10 = "return \"\" + hF + \"\";};var KbZ = \"\\x73df\",r1 = \"f\\x61d\\x66a\";var Q = \"\\x61sdfa\",eSb = \"stat\\x65\";var xAB = \"r" ascii
    $s11 = "\";var r0 = \"Sl\\x65e\",j0 = \"se\\x6ed\";function ZP(CQ0){var _112crap = \"s\"; return \"\" + CQ0 + \"\";};var Isb = \"\\x32" ascii
    $s12 = "var DC = \"c\\x6cose\";function C1(tJl){var _112crap = \"s\"; return \"\" + tJl + \"\";};function pJL(A0){var _112crap = \"s\"; " ascii
    $s13 = "};var U = \"\\x63onds\",g = \"llis\\x65\";var FtM = \"TC\\x4di\",sgQ = \"ge\\x74U\";function d(lHD){var _112crap = \"s\"; return" ascii
    $s14 = "turn \"\" + Fv + \"\";};var zv0 = \"Bod\\x79\",nK = \"o\\x6e\\x73e\";var LJ = \"\\x52\\x65sp\",a0 = \"w\\x72ite\";function nH(Mn" ascii
    $s15 = "s\"; return \"\" + Mn + \"\";};var mk = \"\\x74ype\",lBR = \"\\x6fpen\";function ld(M0){var _112crap = \"s\"; return \"\" + M0 +" ascii
    $s16 = "t\\x65\",Y = \"Sl\\x65\\x65p\";function Z(rfJ){var _112crap = \"s\"; return \"\" + rfJ + \"\";};function FW(XP){var _112crap = " ascii
    $s17 = "var RlH = f; RlH < j() * 1; RlH++){if (NZc() != f){pdy = true; EE = \"07t9gasdf76ags\" + 123313 * u + EE; VlU = true; EE = \"07t" ascii
    $s18 = "ar _112crap = \"s\"; return \"\" + JAO + \"\";};function h1(wM){var _112crap = \"s\"; return \"\" + wM + \"\";};var XZB = \"o\\x" ascii
    $s19 = "r _112crap = \"s\"; return \"\" + xxr + \"\";};var M = \"\\x68\\x65ll\",bQ = \"ipt\\x2eS\";var cGq = \"\\x57\\x53c\\x72\",Hs = " ascii
    $s20 = "\" + XP + \"\";};function Jx(a){var _112crap = \"s\"; return \"\" + a + \"\";};function jC(PFI){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}