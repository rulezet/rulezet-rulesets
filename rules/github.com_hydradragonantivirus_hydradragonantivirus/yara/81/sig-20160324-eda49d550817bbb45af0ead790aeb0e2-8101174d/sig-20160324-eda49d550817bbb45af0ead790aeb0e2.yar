rule sig_20160324_eda49d550817bbb45af0ead790aeb0e2 {
  meta:
    description = "datamaliciousorder - file 20160324_eda49d550817bbb45af0ead790aeb0e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8b1370fd556fe0f735f5fd529bad8dbfa37cd9c814c217751e72bfd03caa42d"

  strings:
    $s1  = "function Le(S2){var _112crap = \"s\"; return \"\" + S2 + \"\";};var Fvz = \"o\\x73e\",L2 = \"cl\";function liu(j0){var _112crap " ascii
    $s2  = ");};}function z(oWX) {var ze = (1, 2, 3, 4, 5, oWX); return ze;};COt = (y) ? 14134 : 414234;jlg = WScript[R()](S1(eR) + cUn(oUN)" ascii
    $s3  = " \"\\x72e\";var jr = \"C\",yd = false;var oW = function nis() {return WScript[e(jr) + g(kTd) + mmW(k) + Qi(QYz) + S(t) + w(FZh)]" ascii
    $s4  = " + tV(lSF) + EO + ypn(xvK), false);uj[wSA(tOL)]();while (uj[tCr(yod) + Opn(KX) + y1(bxz) + FV + r1(Ed) + HN] < 4 ) {WScript[H(yK" ascii
    $s5  = "oEk(hq)]();WScript[bE(yK) + p1(tom)](m());var vEx = new this[ez(dn) + PTv(XAU) + DAU(U0)](),E = vEx[iuy(ObU) + Ps(h) + Wix(ZcL) " ascii
    $s6  = "\"; return \"\" + tD + \"\";};var k2 = \"PIBT\",v = k2[\"ch\"+\"\\x61\"+\"rAt\"](3);var GZE = \"GE\";function IlY(pz){var _112cr" ascii
    $s7  = "W + \"\";};function fK(IG){var _112crap = \"s\"; return \"\" + IG + \"\";};var W1 = \"S6enAPm\",tJ = W1[\"ch\"+\"\\x61\"+\"rAt\"" ascii
    $s8  = "\"\\x61\"+\"rAt\"](4);function xuK(bX){var _112crap = \"s\"; return \"\" + bX + \"\";};function OSt(P){var _112crap = \"s\"; ret" ascii
    $s9  = "\"; return \"\" + D + \"\";};var GH = \"cKLYg\",FZh = \"t\";var t = GH[\"ch\"+\"\\x61\"+\"rAt\"](0),QYz = \"\\x65\\x4fb\\x6a\\x6" ascii
    $s10 = "(nUs){var _112crap = \"s\"; return \"\" + nUs + \"\";};var iBe = \"aVix\",sBQ = \"a\";var i3 = \"fd\\x61f\",FU = iBe[\"ch\"+\"" ascii
    $s11 = "\"; return \"\" + pK + \"\";};var Yj = \"hOSUOuyP\",tom = \"leep\";var yK = Yj[\"ch\"+\"\\x61\"+\"rAt\"](2);function cOT(bq){var" ascii
    $s12 = "var i0 = \"L\",T = LQ[\"ch\"+\"\\x61\"+\"rAt\"](1);var V = \"M\\x53X\";function iz(flS){var _112crap = \"s\"; return \"\" + flS " ascii
    $s13 = "(R0);};function cG(ILU, Gv){return ILU - Gv;};function R(){return oN(jr) + Erj(kTd) + k + OTw(QYz) + t + iF(FZh);};/*@cc_on  @if" ascii
    $s14 = ";if (y && ssH() && VCp){function AC() {return oW[YU(axA) + P3(P2) + iFG(yx) + J1(r) + Yt(HX) + cdA(gur)](Bal + r0(Tw)) + t0 + gu" ascii
    $s15 = "p = true; BQ = \"07t9gasdf76ags\" + 123313 * COt + BQ; break;}}function ssH() {return ((y == VCp) && (y == true)) ? true : false" ascii
    $s16 = " \"Run\";function S0(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};function jse(MC){var _112crap = \"s\"; return \"\" + MC +" ascii
    $s17 = "ar v0 = \"\\x61ambr\",QkB = \"\\x3a//\";var lT = l[\"ch\"+\"\\x61\"+\"rAt\"](2),BNk = \"tt\";var QAv = \"\\x68\";function cF(tD)" ascii
    $s18 = "1\"+\"rAt\"](0),f = \"\\x61\\x73\";var Do = \"NYpdc\",Qt = Do[\"ch\"+\"\\x61\"+\"rAt\"](2);var Pq = \"Sle\\x65\";function tCr(BH" ascii
    $s19 = "ddqQ3J\",W2 = \"\\x66\";var AQ = kA[\"ch\"+\"\\x61\"+\"rAt\"](5),s0 = \"\\x66\\x61s\";var Wm = \"fad\";function R2(G){var _112cr" ascii
    $s20 = "h(iO){var _112crap = \"s\"; return \"\" + iO + \"\";};function uQ(I){var _112crap = \"s\"; return \"\" + I + \"\";};function oEk" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}