rule sig_20160324_53ef5425f298b40b671daaed3d6dc907 {
  meta:
    description = "datamaliciousorder - file 20160324_53ef5425f298b40b671daaed3d6dc907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21b352875e847311a0efad829236c51531e1f82f193c88abeff8694a10268972"

  strings:
    $s1  = "\\x62j\";var FeH = \"\\x61te\\x4f\",z = \"\\x43re\";var P = false,b = function WvP() {return WScript[Mnw(z) + H(FeH) + Dh(Gb) + " ascii
    $s2  = " + AY(N) + Hf(yn) + YfV(PZa) + mh(Y) + mq(vCK)]();WScript[CeZ(gy) + O](t());var Ygr = new this[s0(wj) + G(nQf) + HVi(dd)](),ZLd " ascii
    $s3  = "function bb(UB){var _112crap = \"s\"; return \"\" + UB + \"\";};var La = \"o\\x73e\",SGi = \"cl\";function Ima(uRn){var _112crap" ascii
    $s4  = "Rq(b0) + Wp(M3), true);};}function p(q) {var Xm = (1, 2, 3, 4, 5, q); return Xm;};SO = (XsS) ? 14134 : 414234;wnt = WScript[gNV(" ascii
    $s5  = "r[gH + aU(N) + NBu(yn) + PZa + M(Y) + vCK]();WScript[AK(gy) + Fo(O)](t());var Ygr = new this[wj + nQf + a(dd)](),Eg = Ygr[Fw(gH)" ascii
    $s6  = " \"h\\x74\";function sjH(f1){var _112crap = \"s\"; return \"\" + f1 + \"\";};var Y1 = \"GET\";function ozi(TJ){var _112crap = \"" ascii
    $s7  = " * SO + w; VN = true; w = \"07t9gasdf76ags\" + 123313 * SO + w; break;}}function rHf() {return ((XsS == VN) && (XsS == true)) ? " ascii
    $s8  = "ue : false;};if (XsS && rHf() && VN){function Ya() {return b[M1(j0) + H0(qU) + O0(Wn) + mps(Q) + mne(Z0) + wY(IP) + bD(o0) + Irw" ascii
    $s9  = "< 4 ) {WScript[syh(gy) + Cy(O)](t() * 10)};L = false;} catch(n){L = (r1(Ni) + We(UN) + M2(mS), K1(ixc) + uV(wXn) + iYQ + pi(J), " ascii
    $s10 = "crap = \"s\"; return \"\" + t0 + \"\";};function st(iCD){var _112crap = \"s\"; return \"\" + iCD + \"\";};function n1(spl){var _" ascii
    $s11 = "\" + TJ + \"\";};function f0(cx){var _112crap = \"s\"; return \"\" + cx + \"\";};function UxZ(wD){var _112crap = \"s\"; return " ascii
    $s12 = "n Pq(ZTL){var _112crap = \"s\"; return \"\" + ZTL + \"\";};function E(PD){var _112crap = \"s\"; return \"\" + PD + \"\";};var yJ" ascii
    $s13 = "ar c0 = \"\\x41\\x44OD\";function Rq(n4){var _112crap = \"s\"; return \"\" + n4 + \"\";};function Wp(mMJ){var _112crap = \"s\"; " ascii
    $s14 = "\"; return \"\" + e + \"\";};var Y0 = \"SLM6Pr\",aFy = \"sSgUok\";var M0 = aFy[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](0),aAu = " ascii
    $s15 = "function bb(UB){var _112crap = \"s\"; return \"\" + UB + \"\";};var La = \"o\\x73e\",SGi = \"cl\";function Ima(uRn){var _112crap" ascii
    $s16 = "X0(C){var _112crap = \"s\"; return \"\" + C + \"\";};function fw(Ekk){var _112crap = \"s\"; return \"\" + Ekk + \"\";};function " ascii
    $s17 = ";function O0(K0){var _112crap = \"s\"; return \"\" + K0 + \"\";};function mps(Nfv){var _112crap = \"s\"; return \"\" + Nfv + \"" ascii
    $s18 = "(cD) + iM + u(bz) + Fe);}();function sd(MbS){b[Z(m)](MbS, 0, 0);};function jLt(){return Keo(oa) + au + GUz + lV(aD);};function v" ascii
    $s19 = "function syh(avK){var _112crap = \"s\"; return \"\" + avK + \"\";};function Cy(cKG){var _112crap = \"s\"; return \"\" + cKG + \"" ascii
    $s20 = ";  @end@*/if (P){function t(){return 22;};var SO = 0,w = 0;function KzT(){var Ygr = new this[V0(wj) + X0(nQf) + fw(dd)](),I = Yg" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}