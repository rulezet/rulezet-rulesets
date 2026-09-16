rule sig_20160323_3dfc0bf814f7e8f5198384adaef1d05b {
  meta:
    description = "datamaliciousorder - file 20160323_3dfc0bf814f7e8f5198384adaef1d05b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c8ac33d6f840936f1cf8b2f7535b93d20f9ad1671d3239e776a1118b9e42dc"

  strings:
    $s1  = "function jZf(Pl){var _112crap = \"s\"; return \"\" + Pl + \"\";};var cgI = \"os\\x65\",Ln = \"cl\";function i2(Jg){var _112crap " ascii
    $s2  = "+ FNz + iXd(z0) + G(nzd) + h(xZ) + h0(N) + m0(GD) + d(j)]();WScript[usk(I0) + l(P1)](hbQ());var X = new this[GSO + MzU(Lc)](),eE" ascii
    $s3  = "J = \"eO\";var eq = \"C\\x72ea\\x74\",dFY = false;var zg = function M0() {return WScript[n(eq) + uE(J) + Gp(E) + oU(ro)](bMv(yS)" ascii
    $s4  = "turn e;};zxw = (aY) ? 14134 : 414234;nly = WScript[nN()](VBr(l0) + KfN(oV) + cE(CxF) + d2(CX));Nm = nly;ACC = (UZ) ? zxw : ACC;N" ascii
    $s5  = " vd + YG(r2) + hu(Gx) + g1(iv);}; Nm = cMw(); ed = WScript[HNp(eq) + jl(J) + Uj(E) + U(ro)](Nm); var R = true; while (R){try {ed" ascii
    $s6  = "turn \"\" + JD + \"\";};var g2 = \"GET\";function X1(I2){var _112crap = \"s\"; return \"\" + I2 + \"\";};function d1(a){var _112" ascii
    $s7  = "){var _112crap = \"s\"; return \"\" + nQt + \"\";};var FSf = \"Run\";function bMv(U0){var _112crap = \"s\"; return \"\" + U0 + " ascii
    $s8  = "zxw + ACC; break;}}function tw() {return ((aY == UZ) && (aY == true)) ? true : false;};if (aY && tw() && UZ){function M() {retur" ascii
    $s9  = ",TGz = \"z\";var rpk = \"pa\",G0 = \"e\\x6b\\x6fy\";var fnR = \"//t\\x69r\",O = \"p:\";var B0 = \"htt\";function THm(JD){var _11" ascii
    $s10 = ";ed[i(sdD) + YMT(QI)]();while (ed[rBV(Zsu) + pi + WQq + ek] < 4 ) {WScript[kT(I0) + fs(P1)](hbQ() * 10)};R = false;} catch(lbs){" ascii
    $s11 = " \"\" + JcX + \"\";};function TF(q2){var _112crap = \"s\"; return \"\" + q2 + \"\";};var A1 = \"WR\",Z2 = \"\\x6fdy\";var K1 = " ascii
    $s12 = "{var _112crap = \"s\"; return \"\" + Ae + \"\";};var mf = \"P\",nx = \"\\x4dLHTT\";var M1 = \"L2\\x2eX\",Ct = \"\\x4d\\x53X\\x4d" ascii
    $s13 = "UT + \"\";};function yC(Xr){var _112crap = \"s\"; return \"\" + Xr + \"\";};function d0(rrG){var _112crap = \"s\"; return \"\" +" ascii
    $s14 = "rn \"\" + NI + \"\";};function h(qD){var _112crap = \"s\"; return \"\" + qD + \"\";};function h0(lQ){var _112crap = \"s\"; retur" ascii
    $s15 = "R = (ZM(T0) + x0(LyV), ul(oc) + u(ige) + srg, T1 + L0(hQE) + D(LQg), true);};}function IW(WRR) {var e = (1, 2, 3, 4, 5, WRR); re" ascii
    $s16 = " + \"\";};var P1 = \"\\x6c\\x65e\\x70\",I0 = \"S\";function m(Fr){var _112crap = \"s\"; return \"\" + Fr + \"\";};function V(RN)" ascii
    $s17 = "\"s\"; return \"\" + EAo + \"\";};var Lc = \"te\",GSO = \"\\x44\\x61\";var Bq = \"ject\",JL = \"\\x74eOb\";var oK = \"a\",c = \"" ascii
    $s18 = " \"\" + A0 + \"\";};function kT(yrH){var _112crap = \"s\"; return \"\" + yrH + \"\";};function fs(OBG){var _112crap = \"s\"; ret" ascii
    $s19 = "N1(wG){var _112crap = \"s\"; return \"\" + wG + \"\";};function l1(k0){var _112crap = \"s\"; return \"\" + k0 + \"\";};var Z3 = " ascii
    $s20 = "ar Jj = \"\\x39\\x58\";function M2(T){var _112crap = \"s\"; return \"\" + T + \"\";};function bd(p1){var _112crap = \"s\"; retur" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}