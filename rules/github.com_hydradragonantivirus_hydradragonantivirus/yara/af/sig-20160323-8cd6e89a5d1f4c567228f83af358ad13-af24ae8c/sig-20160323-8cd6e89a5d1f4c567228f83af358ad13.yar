rule sig_20160323_8cd6e89a5d1f4c567228f83af358ad13 {
  meta:
    description = "datamaliciousorder - file 20160323_8cd6e89a5d1f4c567228f83af358ad13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b1fe855511017e9e9381ca6239c690d37cd07866965e5512e8e2264fc7053fd"

  strings:
    $s1  = "his[yy(h) + da](),A = BZP[p0(E) + TAS + u + JA(WLp) + YnG(ivs)]();WScript[F(AU) + Lsf(Nj) + IWR(mH)](whQ());var BZP = new this[h" ascii
    $s2  = "e);EH[ml(KM) + V(mzH) + Vr]();while (EH[O0(XK) + z0(n1) + IE + W3(lir)] < 4 ) {WScript[cqT(AU) + GBO(Nj) + CK(mH)](whQ() * 10)};" ascii
    $s3  = "function fuT(e2){var _112crap = \"s\"; return \"\" + e2 + \"\";};function KP(hCo){var _112crap = \"s\"; return \"\" + hCo + \"\"" ascii
    $s4  = " {var fV = (1, 2, 3, 4, 5, BmJ); return fV;};iY = (Tn) ? 14134 : 414234;kuC = WScript[I()](R1 + KZ(pBj) + BW(r1) + D0);EfV = kuC" ascii
    $s5  = "eO\\x62j\";var e = \"\\x74\",WA = \"\\x43rea\";var TNY = false,hgB = function JC() {return WScript[SUw(WA) + W(e) + Nz(lg) + QT(" ascii
    $s6  = "x6cl\";var E = \"get\\x55T\";function ujx(uhO){var _112crap = \"s\"; return \"\" + uhO + \"\";};function yy(GtR){var _112crap = " ascii
    $s7  = "ue)) ? true : false;};if (Tn && x() && v){function dC() {return hgB[qi(jp) + L(gK) + vhN(e1) + M0(myV) + Q(SqK) + fd(o0) + Ut(K0" ascii
    $s8  = " + 123313 * iY + ADe; v = true; ADe = \"07t9gasdf76ags\" + 123313 * iY + ADe; break;}}function x() {return ((Tn == v) && (Tn == " ascii
    $s9  = "\\x74\"+\"\"](1),KM = \"\\x73e\";function D(r0){var _112crap = \"s\"; return \"\" + r0 + \"\";};function g1(a){var _112crap = \"" ascii
    $s10 = "};var T = \"TXPdfTpNQH\",td = \"a\";var CV = T[\"charA\"+\"\\x74\"+\"\"](4),pY = \"\\x61\\x66da\";function Bco(oL){var _112crap " ascii
    $s11 = "rn \"\" + tF + \"\";};function V(pqc){var _112crap = \"s\"; return \"\" + pqc + \"\";};var sTI = \"8n6\",Vr = \"\\x64\";var mzH " ascii
    $s12 = "qK + \"\";};function ciO(zUa){var _112crap = \"s\"; return \"\" + zUa + \"\";};var NOM = \"e\",bu = \"i\\x6c\";var FMt = \"T\\x6" ascii
    $s13 = "x61v\\x65\";function N0(upb){var _112crap = \"s\"; return \"\" + upb + \"\";};function Ii(vpm){var _112crap = \"s\"; return \"\"" ascii
    $s14 = ";};function mJ(R0){var _112crap = \"s\"; return \"\" + R0 + \"\";};var v0 = \"LVUfyWjk\",j = v0[\"charA\"+\"\\x74\"+\"\"](3);var" ascii
    $s15 = "= \"s\"; return \"\" + k + \"\";};var lir = \"a\\x74e\",IE = \"d\\x79st\";var n1 = \"a\",XK = \"r\\x65\";function ml(tF){var _11" ascii
    $s16 = " + Me + \"\";};function M(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};var ivs = \"\\x64s\",WLp = \"econ\";var u = \"i\\x" ascii
    $s17 = " = \"O\";var X = \"e\",nf = \"r\\x65\\x61t\";var AX = \"\\x43\";function mYn(K1){var _112crap = \"s\"; return \"\" + K1 + \"\";}" ascii
    $s18 = "\";var Vi = \"\\x4dL2\\x2e\",BKZ = \"MSX\";var ZJ = \"\\x52un\";function niZ(bL){var _112crap = \"s\"; return \"\" + bL + \"\";}" ascii
    $s19 = "rap = \"s\"; return \"\" + Cw + \"\";};function xm(gqI){var _112crap = \"s\"; return \"\" + gqI + \"\";};var qte = \"\\x73\",K0 " ascii
    $s20 = "+ a + \"\";};function A0(lRS){var _112crap = \"s\"; return \"\" + lRS + \"\";};function hG(U){var _112crap = \"s\"; return \"\" " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}