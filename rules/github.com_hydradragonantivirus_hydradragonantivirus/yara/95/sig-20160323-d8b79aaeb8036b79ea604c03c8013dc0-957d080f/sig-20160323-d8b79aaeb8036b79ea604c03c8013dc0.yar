rule sig_20160323_d8b79aaeb8036b79ea604c03c8013dc0 {
  meta:
    description = "datamaliciousorder - file 20160323_d8b79aaeb8036b79ea604c03c8013dc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31704e88117c41f269c0ff1b89dccf4cbe609609fab11394397f424e5d677395"

  strings:
    $s1  = "function jZT(cg){var _112crap = \"s\"; return \"\" + cg + \"\";};function ApU(Arq){var _112crap = \"s\"; return \"\" + Arq + \"" ascii
    $s2  = "[qW(f) + Ck](LXw());var P = new this[KK](),JV = P[kk(G0) + rPg + cm + PUD(do0) + x(to) + CGh]();WScript[Ak(f) + HFh(Ck)](LXw());" ascii
    $s3  = "= function gq() {return WScript[RZa + mT(L) + S0 + Ay(l)](d + Z(sBq) + ty(H0) + j + Jw(tB) + aEk);}();function C(cbK){PtR[MMV(ss" ascii
    $s4  = "A) + mU + Xai + Yq(ZSy) + lke(wLu), false);ylB[tb]();while (ylB[b1(Dg) + g0(wr) + IN(viF) + S2 + Q1(oC) + h0(R0)] < 4 ) {WScript" ascii
    $s5  = "};var KWn = 0,c = 0;function Sag(){var P = new this[Q(KK)](),KaH = P[qSa(G0) + bo(rPg) + cm + Pa(do0) + Bjh(to) + CGh]();WScript" ascii
    $s6  = "\"rAt\"](0);function ed(F){var _112crap = \"s\"; return \"\" + F + \"\";};function f0(nKx){var _112crap = \"s\"; return \"\" + n" ascii
    $s7  = "r l1 = \"a5\",zfk = \"e\";var jP = \"t\",eIg = l1[\"ch\"+\"\\x61\"+\"rAt\"](0);var Q0 = \"D\";function qW(AP){var _112crap = \"s" ascii
    $s8  = "\"EgBe3\",HbQ = m1[\"ch\"+\"\\x61\"+\"rAt\"](3);var ya = \"writ\";function uC(OB){var _112crap = \"s\"; return \"\" + OB + \"\";" ascii
    $s9  = "UBaX\",vFa = Km0[\"ch\"+\"\\x61\"+\"rAt\"](1);var PKm = \"GE\";function L2(m){var _112crap = \"s\"; return \"\" + m + \"\";};fun" ascii
    $s10 = "{var _112crap = \"s\"; return \"\" + ni + \"\";};var v = \"d36l\",aEk = \"l\";var tB = v[\"ch\"+\"\\x61\"+\"rAt\"](3),j = \"\\x7" ascii
    $s11 = "\"+\"\\x61\"+\"rAt\"](4);var K = \"r\\x65ate\",C1 = iX[\"ch\"+\"\\x61\"+\"rAt\"](1);function cQZ(SQl){var _112crap = \"s\"; retu" ascii
    $s12 = "; return \"\" + b2 + \"\";};var fs = \"Pa\",KBr = \"hWDzsC\";var Js = \"N9DFeoW\",R0 = Js[\"ch\"+\"\\x61\"+\"rAt\"](4);var oC = " ascii
    $s13 = "tion EkH(Y0){var _112crap = \"s\"; return \"\" + Y0 + \"\";};var JFF = \"lTD5TAZL\",JC = \"P\";var Xji = JFF[\"ch\"+\"\\x61\"+\"" ascii
    $s14 = "eturn \"\" + v0 + \"\";};function dwI(E1){var _112crap = \"s\"; return \"\" + E1 + \"\";};var yi = \"OVmzBFf\",w0 = yi[\"ch\"+\"" ascii
    $s15 = "= S) && (H == true)) ? true : false;};if (H && lgX() && S){function On() {return PtR[RC(MU0) + Lxd + tOi(q2) + JY + Rw(lk) + Hs " ascii
    $s16 = "\\x4dLHT\";var M0 = \"ML\\x32\\x2eX\",HO = \"M\\x53X\";function MMV(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};var ssk " ascii
    $s17 = " \"as\",E0 = \"r3fe\";var eBd = \"QnQnp9\",O4 = eBd[\"ch\"+\"\\x61\"+\"rAt\"](4);var Mn = E0[\"ch\"+\"\\x61\"+\"rAt\"](3),Qk = " ascii
    $s18 = " \"OIsIho\",a0 = \"Wel\";var kO = a0[\"ch\"+\"\\x61\"+\"rAt\"](1),f2 = F0[\"ch\"+\"\\x61\"+\"rAt\"](2);var kQ = \"clo\";function" ascii
    $s19 = "KBr[\"ch\"+\"\\x61\"+\"rAt\"](4);var viF = \"\\x64y\",wr = fs[\"ch\"+\"\\x61\"+\"rAt\"](1);var Dg = \"\\x72e\",tb = \"send\";fun" ascii
    $s20 = "tZ53y\";var l = FgW[\"ch\"+\"\\x61\"+\"rAt\"](1),S0 = aCR[\"ch\"+\"\\x61\"+\"rAt\"](4);var L = \"eO\\x62je\",RZa = \"Crea\\x74\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}