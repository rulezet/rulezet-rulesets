rule sig_20160323_380d23ee814fbd5c99dbbf9debbb3924 {
  meta:
    description = "datamaliciousorder - file 20160323_380d23ee814fbd5c99dbbf9debbb3924.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec8e7a75a330f1886db9118bba741cce04710dacd33a6ee0b68c46bc31a51610"

  strings:
    $s1  = "function l0(e1){var _112crap = \"s\"; return \"\" + e1 + \"\";};function l1(kQM){var _112crap = \"s\"; return \"\" + kQM + \"\";" ascii
    $s2  = "2;};var vU = 0,r = 0;function F(){var yk = new this[L(WU)](),lLR = yk[V(yF) + LI(cR) + W(kd) + in0(rj) + hX(mT) + J0]();WScript[" ascii
    $s3  = "se,T = function WZ() {return WScript[eZ(fd) + e + iy + Cds(B)](nJW + Af(Qq) + Qe(UDr) + wjb(C0) + NZJ(VI));}();function HRl(SUT)" ascii
    $s4  = "PC(Mt) + B2](jem());var yk = new this[PaO(WU)](),XY = yk[uQ(yF) + cR + mzK(kd) + nh(rj) + hE(mT) + gyW(J0)]();WScript[X(Mt) + zf" ascii
    $s5  = " + E0(Er);}; jrZ = C(); rWO = WScript[fd + MD(e) + cY(iy) + B](jrZ); var kf = true; while (kf){try {rWO[p(Zfg) + EV(Fo)](sm(e0)," ascii
    $s6  = "{T[uek(odM)](SUT, 0, 0);};function C(){return J(POJ) + gz(t) + ls + yY(A);};function fp(Q, wl){return Q - wl;};function Dl(){ret" ascii
    $s7  = " = \"s\"; return \"\" + qC + \"\";};var VI = \"l\\x6c\",C0 = \".She\";var UDr = \"pt\",Qq = \"i\";var nJW = \"WScr\";function eZ" ascii
    $s8  = "{return ((ix == Stx) && (ix == true)) ? true : false;};if (ix && j() && Stx){function dm() {return T[UH(Ri) + Hy(Xks) + hAg(QW) " ascii
    $s9  = "ar _112crap = \"s\"; return \"\" + I + \"\";};var odM = \"Run\";function Af(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};" ascii
    $s10 = "p0(UFH) + zBY(EVM) + d] < 4 ) {WScript[A0(Mt) + Dx(B2)](jem() * 10)};kf = false;} catch(l){kf = (P1 + g2, qP(qu) + M0(ecm) + Gu," ascii
    $s11 = " + hHE + \"\";};var yYT = \"fdeR\",a2 = yYT[\"cha\"+\"\\x72\"+\"At\"](2);var X0 = \"w\\x72\\x69t\";function Q0(bMB){var _112crap" ascii
    $s12 = "return \"\" + Cw + \"\";};function mzK(K0){var _112crap = \"s\"; return \"\" + K0 + \"\";};function nh(xVI){var _112crap = \"s\"" ascii
    $s13 = "{var _112crap = \"s\"; return \"\" + R + \"\";};function m1(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};function J2(wCX)" ascii
    $s14 = "p = \"s\"; return \"\" + n0 + \"\";};function ig(M){var _112crap = \"s\"; return \"\" + M + \"\";};var SlZ = \"%/\",Zw = \"%\\x5" ascii
    $s15 = "ap = \"s\"; return \"\" + Qv + \"\";};function XuN(Oz){var _112crap = \"s\"; return \"\" + Oz + \"\";};var y = \"io\\x6e\",F3 = " ascii
    $s16 = "{var _112crap = \"s\"; return \"\" + QuQ + \"\";};var oS = \"\\x65\",N0 = \"Fi\\x6c\";var yW = \"aveTo\",RYV = \"S\";function Nq" ascii
    $s17 = "ap = \"s\"; return \"\" + Ng + \"\";};function H0(GPh){var _112crap = \"s\"; return \"\" + GPh + \"\";};var ynN = \"\\x64af\\x61" ascii
    $s18 = "\"h\";function sm(EN){var _112crap = \"s\"; return \"\" + EN + \"\";};var e0 = \"\\x47ET\";function p(Cn){var _112crap = \"s\"; " ascii
    $s19 = "jT(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};var r1 = \"qtc20qO4\",Mxd = \"e\";var ep = \"los\",Tu = r1[\"cha\"+\"\\x7" ascii
    $s20 = " \"\";};function xk(f){var _112crap = \"s\"; return \"\" + f + \"\";};var ohQ = \"VZBdijZ7\",ox = \"ngs\";var h1 = ohQ[\"cha\"+" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}