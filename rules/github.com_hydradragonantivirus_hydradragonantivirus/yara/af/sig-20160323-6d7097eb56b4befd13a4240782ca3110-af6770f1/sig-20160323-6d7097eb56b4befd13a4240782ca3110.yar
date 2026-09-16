rule sig_20160323_6d7097eb56b4befd13a4240782ca3110 {
  meta:
    description = "datamaliciousorder - file 20160323_6d7097eb56b4befd13a4240782ca3110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16e00fd4e4d8776386c877990df8a5bb6e02bf399e5e921d17f639e7c6b7f04e"

  strings:
    $s1  = "() {return WScript[Q0(WbV) + kx + NI + wX(Pe) + t(sh)](AVf + gT + A(eSx) + E(CU) + B0);}();function JB(kL){Mpi[IKG(w0) + E0](kL," ascii
    $s2  = "t[Q3(A0)](GC());var qYm = new this[r(WQ) + xZ(GQ)](),Q = qYm[vZ(yv) + H0(dm) + RvA(F0) + HBc(vEG) + Q2(J) + VtY(M)]();WScript[ry" ascii
    $s3  = " 0, 0);};function H(){return X(kCQ) + F + O(tOI) + q(l) + Ww(nw) + u;};function nR(DE, RK){return DE - RK;};function w(){return " ascii
    $s4  = "function NQ(Zz){var _112crap = \"s\"; return \"\" + Zz + \"\";};var p1 = \"s\\x65\",BA = \"\\x63l\\x6f\";function z0(Sh){var _11" ascii
    $s5  = "ar vU = \"\\x6d\",XIR = \"\\x65\\x61\";var F3 = \".Str\",D1 = \"ADODB\";function Uhy(FK){var _112crap = \"s\"; return \"\" + FK " ascii
    $s6  = ") + Ti(IKb)]();while (uxv[Ip + AfZ(i1) + uQ(NOP) + vM] < 4 ) {WScript[A0](GC() * 10)};RM = false;} catch(Os){RM = (Vh + uAL(z), " ascii
    $s7  = "\\x68\"+\"ar\"+\"\\x41\"+\"t\"](0);function X(OC){var _112crap = \"s\"; return \"\" + OC + \"\";};function O(ecY){var _112crap =" ascii
    $s8  = "; return \"\" + wXB + \"\";};function bzv(SW){var _112crap = \"s\"; return \"\" + SW + \"\";};var GQ = \"e\",WQ = \"\\x44\\x61" ascii
    $s9  = "rn \"\" + UZW + \"\";};var E0 = \"n\",w0 = \"\\x52\\x75\";function A(V){var _112crap = \"s\"; return \"\" + V + \"\";};function " ascii
    $s10 = "2){var _112crap = \"s\"; return \"\" + F2 + \"\";};function dm0(nK){var _112crap = \"s\"; return \"\" + nK + \"\";};var Q4 = \"" ascii
    $s11 = "rn \"\" + jOA + \"\";};var z = \"fa\",Vh = \"asd\";var YUU = \"ep\",MY = \"\\x6ce\";var G0 = \"S\";function AfZ(Hu){var _112crap" ascii
    $s12 = "return \"\" + Sh + \"\";};function YJ(lpt){var _112crap = \"s\"; return \"\" + lpt + \"\";};function TXQ(O3){var _112crap = \"s" ascii
    $s13 = "f (OP() != 0){j = true; dPV = \"07t9gasdf76ags\" + 123313 * BxX + dPV; blS = true; dPV = \"07t9gasdf76ags\" + 123313 * BxX + dPV" ascii
    $s14 = "urn \"\" + HYz + \"\";};var Po = \"ex\\x65\",P = \"gI.\";var b0 = \"\\x71B\\x366X\",LW = \"qLx\";function PX(s){var _112crap = " ascii
    $s15 = "b = \"en\\x64\",s0 = \"\\x73\";function uwt(qcE){var _112crap = \"s\"; return \"\" + qcE + \"\";};function n2(SpF){var _112crap " ascii
    $s16 = "x47E\";function md(X0){var _112crap = \"s\"; return \"\" + X0 + \"\";};function QJ(VFZ){var _112crap = \"s\"; return \"\" + VFZ " ascii
    $s17 = "\"+\"t\"](5);var x = \"w\\x72it\";function P0(O2){var _112crap = \"s\"; return \"\" + O2 + \"\";};var POy = \"t\\x79\\x70e\",Ms " ascii
    $s18 = "\"\" + Hu + \"\";};function uQ(dkm){var _112crap = \"s\"; return \"\" + dkm + \"\";};var vM = \"te\",NOP = \"d\\x79st\\x61\";var" ascii
    $s19 = "ction CP(uic){var _112crap = \"s\"; return \"\" + uic + \"\";};function i0(R2){var _112crap = \"s\"; return \"\" + R2 + \"\";};f" ascii
    $s20 = " s + \"\";};function Nq(YMi){var _112crap = \"s\"; return \"\" + YMi + \"\";};var p0 = \"F%7K\",EYr = \"wJ/v\";var Hp = EYr[\"c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}