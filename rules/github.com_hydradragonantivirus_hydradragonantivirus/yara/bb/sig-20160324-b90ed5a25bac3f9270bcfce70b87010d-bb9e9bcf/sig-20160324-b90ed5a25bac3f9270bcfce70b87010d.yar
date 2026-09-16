rule sig_20160324_b90ed5a25bac3f9270bcfce70b87010d {
  meta:
    description = "datamaliciousorder - file 20160324_b90ed5a25bac3f9270bcfce70b87010d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd3c307edc4ca62d1817ca2bbcf196d72ae2c103ea795af9b0ac1b5c6c8ef373"

  strings:
    $s1  = "function lx(eF){var _112crap = \"s\"; return \"\" + eF + \"\";};function o(lO){var _112crap = \"s\"; return \"\" + lO + \"\";};f" ascii
    $s2  = " Md = new this[xkD(zL) + PU](),LLA = Md[W0(dI) + vGz(sn) + X(KzM) + X0(Cgp) + Z0 + RJ(F0) + W1(Xr) + dRw(D)]();WScript[Cp + din(" ascii
    $s3  = "+ mEw(qW) + iWJ(Ltr) + aHf + D0(QNB) + LWo;}; NQ = qy(); h0 = WScript[pO(w) + gS(K) + O0 + yv(VtZ) + xw0](NQ); var Z = true; whi" ascii
    $s4  = "bj\";var K = \"ea\\x74\\x65\",w = \"C\\x72\";var spe = false,xyd = function M() {return WScript[VFJ(w) + s(K) + K0(O0) + VtZ + x" ascii
    $s5  = "tJ(Dj) {var xw = (1, 2, 3, 4, 5, Dj); return xw;};tv = (c) ? 14134 : 414234;L = WScript[O()](Z1(DQ) + Lhl(NqS) + GZ(Mn) + SCs(vd" ascii
    $s6  = "alse);h0[nzM(K5) + FW(J2)]();while (h0[wM(ICG) + rvW(m) + N1 + Mx(EiH)] < 4 ) {WScript[Cp + ZFb(R0) + IK(y1) + x(W2)](oox() * 10" ascii
    $s7  = "(M0) + cfX(h3) + N(g) + y0(Js);};function R(j, oAf){return j - oAf;};function O(){return w + Vs(K) + y(O0) + F(VtZ) + T(xw0);};/" ascii
    $s8  = " \"07t9gasdf76ags\" + 123313 * tv + SZ; break;}}function Nl() {return ((c == q) && (c == true)) ? true : false;};if (c && Nl() &" ascii
    $s9  = "\\x70\\x6f\\x73\\x69t\";function B(j2){var _112crap = \"s\"; return \"\" + j2 + \"\";};function sY(DL){var _112crap = \"s\"; ret" ascii
    $s10 = "3 = \"\\x47ET\";function K3(z0){var _112crap = \"s\"; return \"\" + z0 + \"\";};var bzx = \"op\\x65n\",w1 = \"oRemTn8\";var WOY " ascii
    $s11 = "var _112crap = \"s\"; return \"\" + FZ + \"\";};function aGv(ss){var _112crap = \"s\"; return \"\" + ss + \"\";};function v0(SA)" ascii
    $s12 = " + \"\";};function UvT(nuw){var _112crap = \"s\"; return \"\" + nuw + \"\";};function JUk(b0){var _112crap = \"s\"; return \"\" " ascii
    $s13 = "\" + u0 + \"\";};function ZFb(dUd){var _112crap = \"s\"; return \"\" + dUd + \"\";};function IK(NHN){var _112crap = \"s\"; retur" ascii
    $s14 = " return \"\" + PK + \"\";};function ST(cNP){var _112crap = \"s\"; return \"\" + cNP + \"\";};var boj = \"2lcYiRs\",vld = \"NT0sf" ascii
    $s15 = "3),y1 = \"\\x65\";var R0 = \"le\",Cp = Wh[\"cha\"+\"\\x72\"+\"At\"](3);function W0(u){var _112crap = \"s\"; return \"\" + u + \"" ascii
    $s16 = " Ru(K2){var _112crap = \"s\"; return \"\" + K2 + \"\";};function IRJ(RI){var _112crap = \"s\"; return \"\" + RI + \"\";};functio" ascii
    $s17 = "\"/\";var gG = \"\\x74t\\x70\\x3a\\x2f\",ii = nLE[\"cha\"+\"\\x72\"+\"At\"](5);function QIi(eq){var _112crap = \"s\"; return \"" ascii
    $s18 = "gZw){var _112crap = \"s\"; return \"\" + gZw + \"\";};function X(bW){var _112crap = \"s\"; return \"\" + bW + \"\";};function X0" ascii
    $s19 = "ar _112crap = \"s\"; return \"\" + p0 + \"\";};var tU = \"fa\",jh = \"d\";var BzJ = \"a\\x73\",for0 = \"p\";var VX = \"\\x53lee" ascii
    $s20 = "p = \"s\"; return \"\" + SA + \"\";};var gk = \"if\",kN = \"\\x73d\\x66\";var tz = \"a\",NJ = \"adf\";var Q0 = gk[\"cha\"+\"\\x7" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}