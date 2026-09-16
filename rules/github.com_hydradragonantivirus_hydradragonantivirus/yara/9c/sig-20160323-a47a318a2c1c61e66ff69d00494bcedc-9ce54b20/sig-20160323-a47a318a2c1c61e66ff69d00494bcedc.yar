rule sig_20160323_a47a318a2c1c61e66ff69d00494bcedc {
  meta:
    description = "datamaliciousorder - file 20160323_a47a318a2c1c61e66ff69d00494bcedc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24fc904936d3526c0a98048b21b1c1c9ba6fbfcab45004f6bd812e9a22a7661e"

  strings:
    $s1  = "var bQ = \"cl\\x6f\\x73e\";function KW(BHA){var _112crap = \"s\"; return \"\" + BHA + \"\";};function Hh(nU){var _112crap = \"s" ascii
    $s2  = "nction dq(e) {var Etr = (1, 2, 3, 4, 5, e); return Etr;};kw = (mmw) ? 14134 : 414234;XLO = WScript[xXD()](EfU + H1(hrC) + iG(g1)" ascii
    $s3  = "FKt = Ky[z + CrT(vhI) + POq(RWJ) + AnW(e0) + Wfq]();WScript[E(bw)](pv());var Ky = new this[LYf(Gt) + W0(tD)](),Zx = Ky[wkG(z) + " ascii
    $s4  = "ew this[MB(Gt) + tD](),qn = Ky[dx(z) + aSF(vhI) + RWJ + pcT(e0) + Wfq]();WScript[ZE(bw)](pv());var Ky = new this[Mi(Gt) + tD]()," ascii
    $s5  = "q(); Ck = WScript[bfC + NDi(LyW) + m1(R) + t(U) + yeS](i0); var bE = true; while (bE){try {Ck[f0(xgH) + h0](sm, Ty(O0) + qjB(uA)" ascii
    $s6  = " = \"b\\x6a\";var R = \"te\\x4f\",LyW = \"a\";var bfC = \"Cre\",xxL = false;var J = function m() {return WScript[kqb(bfC) + D(Ly" ascii
    $s7  = "T0 = \"\\x79\";var Qge = g2[\"ch\"+\"\\x61\"+\"rAt\"](1),xa = \"en\";var X1 = \"op\";function H1(y0){var _112crap = \"s\"; retur" ascii
    $s8  = "\"\\x65\\x61dy\";var bY = sM[\"ch\"+\"\\x61\"+\"rAt\"](2);function r(JS){var _112crap = \"s\"; return \"\" + JS + \"\";};var N0 " ascii
    $s9  = " MI = \"getU\\x54\",sf = \"t\\x65\";var xFx = \"D\\x61\";function ZE(Go){var _112crap = \"s\"; return \"\" + Go + \"\";};functio" ascii
    $s10 = "crap = \"s\"; return \"\" + VXt + \"\";};var Eh = \"wxZpW1f7\",Dho = \"Body\";var kbi = \"o\\x6es\\x65\",u = Eh[\"ch\"+\"\\x61\"" ascii
    $s11 = "HLG + OZ + UU;};function Xx(a, VF){return a - VF;};function xXD(){return ZhT(bfC) + yYL(LyW) + G(R) + o(U) + BDS(yeS);};/*@cc_on" ascii
    $s12 = "PR; se = true; GPR = \"07t9gasdf76ags\" + 123313 * kw + GPR; break;}}function LfT() {return ((mmw == se) && (mmw == true)) ? tru" ascii
    $s13 = ": false;};if (mmw && LfT() && se){function IiU() {return J[BPv(zuf) + w(A) + uEu(yqO) + M0(YXz) + udt(j) + qXi(NP) + oh(diq) + R" ascii
    $s14 = " ) {WScript[bL(bw)](pv() * 10)};bE = false;} catch(Qc){bE = (S1 + ty(B1), n0(BMa) + w2(BfE) + pU, ATf(B2) + N1(OZ0), true);};}fu" ascii
    $s15 = "wy[\"ch\"+\"\\x61\"+\"rAt\"](0),z0 = \"bgskSLIt3\";var L = \"le\\x65\\x70\",W1 = z0[\"ch\"+\"\\x61\"+\"rAt\"](4);function XQN(Ah" ascii
    $s16 = "\\x4c\";function zFJ(M){var _112crap = \"s\"; return \"\" + M + \"\";};var a0 = \"R\\x75n\";function vT(Blf){var _112crap = \"s" ascii
    $s17 = "OqiEm\",dhu = F0[\"ch\"+\"\\x61\"+\"rAt\"](5);var g1 = \"rea\",hrC = \"\\x44\\x42.St\";var EfU = \"\\x41DO\";function ATf(w3){va" ascii
    $s18 = "+ I0 + \"\";};function Bm(iER){var _112crap = \"s\"; return \"\" + iER + \"\";};function Y(p){var _112crap = \"s\"; return \"\" " ascii
    $s19 = "C\\x72e\\x61t\";function DP(O){var _112crap = \"s\"; return \"\" + O + \"\";};var UU = \"TTP\",OZ = \"\\x4dLH\";var HLG = \"2\\x" ascii
    $s20 = "\" + o3 + \"\";};function O1(kg){var _112crap = \"s\"; return \"\" + kg + \"\";};var sM = \"mwrCdk0\",oh0 = \"t\\x61\\x74e\";var" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}