rule sig_20160323_dbedcd434df56d1d89218617ceb0c66a {
  meta:
    description = "datamaliciousorder - file 20160323_dbedcd434df56d1d89218617ceb0c66a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ceb78cb0a4cf35bad64dbfbad695eb7cdb641412ded0d08ff3b740582c4033b"

  strings:
    $s1  = " d0(jPT);}; LOH = j(); h = WScript[L(e) + fRC(buk) + AX(NK) + RZH(zD)](LOH); var F = true; while (F){try {h[qm(upO) + OGB](wv(z2" ascii
    $s2  = "= false,m = function eN() {return WScript[FzW(e) + SsI(buk) + xt(NK) + k(zD)](xz(s) + vvv + s0 + pR(ZS) + Cmk(o) + an);}();funct" ascii
    $s3  = "Edz]();WScript[nPS(xv)](P());var jTa = new this[hpq(soC) + vP](),QW = jTa[sGH(dBo) + D(Pdg) + b0(FLO) + kP(ywA) + u(Edz)]();WScr" ascii
    $s4  = "ion fP(H0){m[fj](H0, 0, 0);};function j(){return Q(U0) + PIZ(lS) + h0(ad) + vuG + lDt + q;};function H(Dbc, r){return Dbc - r;};" ascii
    $s5  = "n Jsp() {return ((hBg == G) && (hBg == true)) ? true : false;};if (hBg && Jsp() && G){function NT() {return m[ie(Q0) + A0(mR) + " ascii
    $s6  = "function s1(SRZ){var _112crap = \"s\"; return \"\" + SRZ + \"\";};function Xp(NB){var _112crap = \"s\"; return \"\" + NB + \"\";" ascii
    $s7  = "g)]();while (h[D0 + Ch(xqa) + K1(efH) + jna(b1) + MQ(ux)] < 4 ) {WScript[xv](P() * 10)};F = false;} catch(d){F = (Tn + BPj(pq0) " ascii
    $s8  = "\\x73e\",Dt = \"\\x63lo\";function iOp(h2){var _112crap = \"s\"; return \"\" + h2 + \"\";};function lc(uC){var _112crap = \"s\";" ascii
    $s9  = "\\x65ct\";var w = \"Obj\",PMD = \"t\\x65\";var R1 = \"ea\",aDr = \"Cr\";function vtK(eP){var _112crap = \"s\"; return \"\" + eP " ascii
    $s10 = "Xh){var _112crap = \"s\"; return \"\" + Xh + \"\";};function i0(Q2){var _112crap = \"s\"; return \"\" + Q2 + \"\";};var ihR = \"" ascii
    $s11 = "n P(){return 22;};var DZc = 0,vY = 0;function yY(){var jTa = new this[pa(soC) + vP](),a = jTa[r0(dBo) + B(Pdg) + Z(FLO) + ywA + " ascii
    $s12 = "function s1(SRZ){var _112crap = \"s\"; return \"\" + SRZ + \"\";};function Xp(NB){var _112crap = \"s\"; return \"\" + NB + \"\";" ascii
    $s13 = "ion RZH(J){var _112crap = \"s\"; return \"\" + J + \"\";};var zD = \"ct\",NK = \"\\x6ae\";var buk = \"\\x61\\x74eOb\",e = \"\\x4" ascii
    $s14 = "= 0){hBg = true; vY = \"07t9gasdf76ags\" + 123313 * DZc + vY; G = true; vY = \"07t9gasdf76ags\" + 123313 * DZc + vY; break;}}fun" ascii
    $s15 = "n + \"\";};function z1(SF){var _112crap = \"s\"; return \"\" + SF + \"\";};function lBQ(Hw){var _112crap = \"s\"; return \"\" + " ascii
    $s16 = " = \"te\";var dE = \"\\x44a\";function nPS(xma){var _112crap = \"s\"; return \"\" + xma + \"\";};function J0(z0){var _112crap = " ascii
    $s17 = "ction sjw(GH){var _112crap = \"s\"; return \"\" + GH + \"\";};function q1(F1){var _112crap = \"s\"; return \"\" + F1 + \"\";};fu" ascii
    $s18 = "unction Tyz(hA){var _112crap = \"s\"; return \"\" + hA + \"\";};var BfZ = \"a\",pq0 = \"f\";var Tn = \"\\x61s\\x64\",yOg = \"\\x" ascii
    $s19 = "n \"\" + sK + \"\";};function k0(e0){var _112crap = \"s\"; return \"\" + e0 + \"\";};function L(dCO){var _112crap = \"s\"; retur" ascii
    $s20 = " \"\" + WVU + \"\";};function H1(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};var Ezc = \"e\\x61\\x6d\",i2 = \"tr\";var la " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}