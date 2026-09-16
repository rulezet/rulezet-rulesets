rule sig_20160323_cfcc869253605fdfb21e138a36677025 {
  meta:
    description = "datamaliciousorder - file 20160323_cfcc869253605fdfb21e138a36677025.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b2ed938602dd89b214054ae3cc65456caba6d328fdfd046d795c59b520a952a"

  strings:
    $s1  = "function QOh(QZ){var _112crap = \"s\"; return \"\" + QZ + \"\";};function zmV(v0){var _112crap = \"s\"; return \"\" + v0 + \"\";" ascii
    $s2  = "getUT\",bqp = \"PeUw\";var N0 = bqp[\"ch\"+\"\\x61\"+\"rAt\"](1),OG = \"D\\x61t\";function VJ(V1){var _112crap = \"s\"; return " ascii
    $s3  = "eturn WScript[E0(Si) + M + a(F) + dJ(x) + V(SeZ)](IB(zvP) + sV + m + oD(huV) + bdG(uv) + cs(di));}();function rc(biy){cw[rvs(XdO" ascii
    $s4  = "\\x61\"+\"rAt\"](3);var IKR = \"\\x41D\";function d3(G1){var _112crap = \"s\"; return \"\" + G1 + \"\";};function uMz(b0){var _1" ascii
    $s5  = "Script[VJ(c0) + jmj(e) + e0](Ji());var pK = new this[fg(Ycv) + m2(g0)](),Iw = pK[o1 + Yr(s2) + c + tc + N(Y) + by(O)]();WScript[" ascii
    $s6  = ";}; sPN = vN(); KO = WScript[pf(Si) + f(M) + kJE(F) + EZg(x) + WD(SeZ)](sPN); var D = true; while (D){try {KO[M2(eI)](v + HpO(I)" ascii
    $s7  = "p = \"s\"; return \"\" + q + \"\";};var hhS = \"qxyI2S6o\",e0 = \"ee\\x70\";var e = \"l\",c0 = hhS[\"ch\"+\"\\x61\"+\"rAt\"](5);" ascii
    $s8  = ";function HpO(ET){var _112crap = \"s\"; return \"\" + ET + \"\";};var Sx = \"11qGGPRo\",I = \"ET\";var v = Sx[\"ch\"+\"\\x61\"+" ascii
    $s9  = "pj[\"ch\"+\"\\x61\"+\"rAt\"](0);function E0(X){var _112crap = \"s\"; return \"\" + X + \"\";};function a(o0){var _112crap = \"s" ascii
    $s10 = "IYD + \"\";};var uC = \"SqC6\",b1 = \"le\";var W1 = \"oF\\x69\",myT = \"aveT\";var Fct = uC[\"ch\"+\"\\x61\"+\"rAt\"](0);functio" ascii
    $s11 = ")](biy, 0, 0);};function vN(){return NN + nQ(RE) + G(m0) + cR(irp) + zy(Z) + f0;};function K(Tu, W){return Tu - W;};function S()" ascii
    $s12 = "tion aO() {return ((SSD == Ej) && (SSD == true)) ? true : false;};if (SSD && aO() && Ej){function iV() {return cw[mg(k2) + R(zPh" ascii
    $s13 = ") + hum(NC)] < 4 ) {WScript[k1(c0) + Kt(e) + bPx(e0)](Ji() * 10)};D = false;} catch(pdm){D = (Ti(Z3) + vv(dd), Ne(Q1) + xvf(a2)," ascii
    $s14 = "rAt\"](4),i = \"ex\";var Fbp = \"i.\",K0 = \"\\x68Z\\x57J4\";var O0 = ybf[\"ch\"+\"\\x61\"+\"rAt\"](5),nmk = \"S\\x47\";var Y1 =" ascii
    $s15 = "ln2ei\",qQ = \"c4d\";var Hz = qQ[\"ch\"+\"\\x61\"+\"rAt\"](2),kwd = r0[\"ch\"+\"\\x61\"+\"rAt\"](5);var aeL = \"se\";function JZ" ascii
    $s16 = "\"\\x61\"+\"rAt\"](0),x = L[\"ch\"+\"\\x61\"+\"rAt\"](1);var F = \"je\",M = \"ateO\\x62\";var Si = \"C\\x72e\",Vhm = false;var c" ascii
    $s17 = "p){var _112crap = \"s\"; return \"\" + p + \"\";};function nW(qg){var _112crap = \"s\"; return \"\" + qg + \"\";};function QUt(d" ascii
    $s18 = "n \"\" + Yh + \"\";};function N(lLV){var _112crap = \"s\"; return \"\" + lLV + \"\";};function by(Xb){var _112crap = \"s\"; retu" ascii
    $s19 = "urn \"\" + vCp + \"\";};function si(dbS){var _112crap = \"s\"; return \"\" + dbS + \"\";};function k3(J){var _112crap = \"s\"; r" ascii
    $s20 = "return \"\" + jsr + \"\";};function fg(m1){var _112crap = \"s\"; return \"\" + m1 + \"\";};function m2(cz){var _112crap = \"s\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}