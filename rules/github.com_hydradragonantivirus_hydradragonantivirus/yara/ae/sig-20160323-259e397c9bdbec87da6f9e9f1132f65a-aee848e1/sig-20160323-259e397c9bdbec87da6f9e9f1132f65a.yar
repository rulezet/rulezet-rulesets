rule sig_20160323_259e397c9bdbec87da6f9e9f1132f65a {
  meta:
    description = "datamaliciousorder - file 20160323_259e397c9bdbec87da6f9e9f1132f65a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf848bbc48e98447b0ca7e8f534adb6595b6943884cf6f6b0a4bf04a24c1373c"

  strings:
    $s1  = "function j2(J3){var _112crap = \"s\"; return \"\" + J3 + \"\";};var Xk = \"c\\x6cose\";function jid(E0){var _112crap = \"s\"; re" ascii
    $s2  = "rn \"\" + zG + \"\";};var AwW = \"ect\",J0 = \"Ob\\x6a\";var R = \"\\x74e\",H = \"Crea\";var h = false,l = function x() {return " ascii
    $s3  = "n Qb(){var r = new this[hz + r1](),Mc = r[r2 + ro(sK) + A(k0) + x0 + Wq(fBv) + u]();WScript[qff(wJ) + d(rL)](jQ());var r = new t" ascii
    $s4  = "his[p(hz) + k(r1)](),LZ = r[LNv(r2) + sK + D0(k0) + M1(x0) + t(fBv) + ExJ(u)]();WScript[xr(wJ) + rL](jQ());var r = new this[hz +" ascii
    $s5  = "2, 3, 4, 5, v); return M;};SvI = (oF) ? 14134 : 414234;ZV = WScript[cOV()](i0(Zz) + BO(Erd) + Ryj(Zx));j = ZV;XId = (J) ? SvI : " ascii
    $s6  = "+ Wna(k3) + u0(J2), false);Xm[aP(Kg) + z2(bak)]();while (Xm[rW(wKD) + c(ON) + Ht] < 4 ) {WScript[XrI(wJ) + uV(rL)](jQ() * 10)};s" ascii
    $s7  = "on ud(){return sQa(VcN) + zsy(tZ) + E(Eh) + HC + iG(w);};function Vkm(q, hb){return q - hb;};function cOV(){return H + D(R) + J0" ascii
    $s8  = "& (oF == true)) ? true : false;};if (oF && MA() && J){function Rcj() {return l[r3(YBL) + jnv(BlA) + fU(j1) + mD(W) + bqK + q2(G0" ascii
    $s9  = "\\x70osit\";function ggj(w2){var _112crap = \"s\"; return \"\" + w2 + \"\";};function yy(In){var _112crap = \"s\"; return \"\" +" ascii
    $s10 = "n Wq(xI){var _112crap = \"s\"; return \"\" + xI + \"\";};function LNv(i){var _112crap = \"s\"; return \"\" + i + \"\";};function" ascii
    $s11 = "= \"s\"; return \"\" + R0 + \"\";};function AC(r0){var _112crap = \"s\"; return \"\" + r0 + \"\";};function Uxp(zG){var _112crap" ascii
    $s12 = "= \"s\"; return \"\" + L0 + \"\";};var Ht = \"t\\x65\",ON = \"dyst\\x61\";var wKD = \"\\x72ea\";function aP(Nhe){var _112crap = " ascii
    $s13 = " \"s\"; return \"\" + lhP + \"\";};function ExJ(UUk){var _112crap = \"s\"; return \"\" + UUk + \"\";};function ss(l1){var _112cr" ascii
    $s14 = "rap = \"s\"; return \"\" + BP0 + \"\";};function E(sri){var _112crap = \"s\"; return \"\" + sri + \"\";};function iG(TDw){var _1" ascii
    $s15 = "_112crap = \"s\"; return \"\" + dgY + \"\";};function GY(zPi){var _112crap = \"s\"; return \"\" + zPi + \"\";};function M2(q3){v" ascii
    $s16 = " \"\" + s1 + \"\";};function q2(k1){var _112crap = \"s\"; return \"\" + k1 + \"\";};function bL(z1){var _112crap = \"s\"; return" ascii
    $s17 = " \"s\"; return \"\" + M3 + \"\";};function i1(pm){var _112crap = \"s\"; return \"\" + pm + \"\";};var DL = \"Xudjow5GqAd\",o = " ascii
    $s18 = "\";};function xr(WR){var _112crap = \"s\"; return \"\" + WR + \"\";};function XrI(bw){var _112crap = \"s\"; return \"\" + bw + " ascii
    $s19 = "var _112crap = \"s\"; return \"\" + l0 + \"\";};function k(V){var _112crap = \"s\"; return \"\" + V + \"\";};function SA(UAZ){va" ascii
    $s20 = "d = \"\\x44ate\";function qff(lBy){var _112crap = \"s\"; return \"\" + lBy + \"\";};function d(zv){var _112crap = \"s\"; return " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}