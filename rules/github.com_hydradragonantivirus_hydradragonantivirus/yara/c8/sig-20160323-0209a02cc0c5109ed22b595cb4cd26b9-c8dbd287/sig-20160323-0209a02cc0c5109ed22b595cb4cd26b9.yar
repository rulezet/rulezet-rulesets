rule sig_20160323_0209a02cc0c5109ed22b595cb4cd26b9 {
  meta:
    description = "datamaliciousorder - file 20160323_0209a02cc0c5109ed22b595cb4cd26b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5749f3137c0d18c2f07795dd5f686d1af22538fb17184f9a23a80a7d885daf04"

  strings:
    $s1  = "+\"t\"](5),GI = false;var C = function r() {return WScript[AOO(nhu) + wd(k1) + fAM + Zy(BZ) + btS(FW)](w + zMZ(k2) + d1(RA) + dw" ascii
    $s2  = "VP(H)](),dY = YO[H0 + Zbz + cC(CGY) + Jk(Xrz) + Q0(cW0)]();WScript[SY(oAP) + t0(w0)](s());var YO = new this[lv(cQ) + r1(N) + eq(" ascii
    $s3  = "2, 3, 4, 5, I); return M0;};CvG = (MB) ? 14134 : 414234;WX = WScript[ZEN()](elV + x0(t1) + Y0(D1));Edc = WX;Hwq = (JCY) ? CvG : " ascii
    $s4  = "H)](),v = YO[xT(H0) + iMg(Zbz) + CGY + Psf(Xrz) + Ug(cW0)]();WScript[q(oAP) + lMG(w0)](s());var YO = new this[AK(cQ) + v0(N) + w" ascii
    $s5  = "(l1) + P0(m0) + igI + bUf + Nh, false);k[Wfy]();while (k[Tnp + w1(VL) + O1(lYy)] < 4 ) {WScript[jn(oAP) + W(w0)](s() * 10)};TA =" ascii
    $s6  = "function F1(jUr){var _112crap = \"s\"; return \"\" + jUr + \"\";};function X1(Q2){var _112crap = \"s\"; return \"\" + Q2 + \"\";" ascii
    $s7  = "; return \"\" + IEx + \"\";};function r2(d2){var _112crap = \"s\"; return \"\" + d2 + \"\";};var vK = \"JnsDw\",g = \"yWpJ5sP7vB" ascii
    $s8  = "tion IlQ(d, k0){return d - k0;};function ZEN(){return d0(nhu) + k1 + fAM + jou(BZ) + Nwr(FW);};/*@cc_on  @if (@_win32 || @_win64" ascii
    $s9  = ") && (MB == true)) ? true : false;};if (MB && vAH() && JCY){function RG() {return C[W1(UX) + UZK(go) + aRi + UKz(If) + quc + YVe" ascii
    $s10 = "M\\x53\\x58ML\";function j(P){var _112crap = \"s\"; return \"\" + P + \"\";};var JVQ = \"Run\";function zMZ(MRn){var _112crap = " ascii
    $s11 = "\\x65\\x61\",Nlm = \"C\\x72\";function zeN(Zi){var _112crap = \"s\"; return \"\" + Zi + \"\";};function zjw(mS){var _112crap = " ascii
    $s12 = " mO + \"\";};function P1(Z0){var _112crap = \"s\"; return \"\" + Z0 + \"\";};function kWK(wPP){var _112crap = \"s\"; return \"\"" ascii
    $s13 = "on AK(KgS){var _112crap = \"s\"; return \"\" + KgS + \"\";};function v0(uVS){var _112crap = \"s\"; return \"\" + uVS + \"\";};fu" ascii
    $s14 = "tion z1(Pb){var _112crap = \"s\"; return \"\" + Pb + \"\";};function Q1(u){var _112crap = \"s\"; return \"\" + u + \"\";};var ri" ascii
    $s15 = " + PjW + \"\";};function AWG(q0){var _112crap = \"s\"; return \"\" + q0 + \"\";};function L1(ZOu){var _112crap = \"s\"; return " ascii
    $s16 = "var _112crap = \"s\"; return \"\" + v1 + \"\";};function HCY(WlU){var _112crap = \"s\"; return \"\" + WlU + \"\";};var pVS = \"R" ascii
    $s17 = "d0(Yp){var _112crap = \"s\"; return \"\" + Yp + \"\";};function jou(UvC){var _112crap = \"s\"; return \"\" + UvC + \"\";};functi" ascii
    $s18 = "_112crap = \"s\"; return \"\" + EPU + \"\";};function Psf(hu){var _112crap = \"s\"; return \"\" + hu + \"\";};function Ug(noU){v" ascii
    $s19 = "function F1(jUr){var _112crap = \"s\"; return \"\" + jUr + \"\";};function X1(Q2){var _112crap = \"s\"; return \"\" + Q2 + \"\";" ascii
    $s20 = "return \"\" + avp + \"\";};function Fb(j2){var _112crap = \"s\"; return \"\" + j2 + \"\";};function L2(mO){var _112crap = \"s\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}