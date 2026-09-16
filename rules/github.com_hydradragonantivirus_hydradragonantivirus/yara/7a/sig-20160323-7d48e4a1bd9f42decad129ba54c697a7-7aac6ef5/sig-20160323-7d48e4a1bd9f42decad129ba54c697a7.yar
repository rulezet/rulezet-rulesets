rule sig_20160323_7d48e4a1bd9f42decad129ba54c697a7 {
  meta:
    description = "datamaliciousorder - file 20160323_7d48e4a1bd9f42decad129ba54c697a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f73c63c7cbb18394f5d7ef8632bdf2c7d8349783dd9f7ac0a91fd4bbefa9ac2"

  strings:
    $s1  = "function ExH(cA){var _112crap = \"s\"; return \"\" + cA + \"\";};function q0(TB){var _112crap = \"s\"; return \"\" + TB + \"\";}" ascii
    $s2  = "yj[\"\"+\"\\x63\"+\"harAt\"](5),L = \"\\x43r\";var nHC = false,Sf = function rrh() {return WScript[XmR(L) + CEH(BBZ) + y + jvA(f" ascii
    $s3  = " + r(T1)) + OO(E1) + Qf(F5) + WRi + E2(rct);}; eq = O(); jv = WScript[L + BBZ + LP(y) + D(fZe) + PTD](eq); var Aw = true; while " ascii
    $s4  = "Z(N0)]();WScript[U0 + qH(T0) + LY(Fbn)](ZL());var V = new this[pv + p0](),Hd = V[l3(tW) + F3(iz) + WL(VX) + p1(LK) + a(X1) + ze(" ascii
    $s5  = "3){var _112crap = \"s\"; return \"\" + T3 + \"\";};var qe = \"dLNwia\",FJ = \"fdafa\";var bRD = qe[\"\"+\"\\x63\"+\"harAt\"](5);" ascii
    $s6  = "){var _112crap = \"s\"; return \"\" + ZTX + \"\";};var s2 = \"yYaJPP\",f0 = \"\\x70e\";var S1 = s2[\"\"+\"\\x63\"+\"harAt\"](0)," ascii
    $s7  = "+\"\\x63\"+\"harAt\"](1);function vs(H1){var _112crap = \"s\"; return \"\" + H1 + \"\";};function N(kq){var _112crap = \"s\"; re" ascii
    $s8  = "\"+\"harAt\"](1);var E1 = \"NL\\x69e\";function tn(KvU){var _112crap = \"s\"; return \"\" + KvU + \"\";};function r(ltL){var _11" ascii
    $s9  = "3r\",oaO = he[\"\"+\"\\x63\"+\"harAt\"](2);function XmR(zRX){var _112crap = \"s\"; return \"\" + zRX + \"\";};function CEH(TaF){" ascii
    $s10 = "; return \"\" + P2 + \"\";};var o0 = \"op\\x65\\x6e\",G0 = \"ahA5X\";var Hz = \"ect\",s1 = \"\\x74eOb\\x6a\";var SGW = G0[\"\"+" ascii
    $s11 = "\"\\x63\"+\"harAt\"](4);var XTk = \"Slee\";function C0(XQf){var _112crap = \"s\"; return \"\" + XQf + \"\";};function MM(HfN){va" ascii
    $s12 = "q(t) + f(qL);};function LVw(fSh, KI){return fSh - KI;};function ILw(){return X0(L) + BBZ + Hu(y) + fZe + Izx(PTD);};/*@cc_on  @i" ascii
    $s13 = "c && d() && UqG){function ie() {return Sf[Hzy + m(F4) + Qv(Nst) + Qfr(sE) + YYR(UP) + UI(vM) + KbP(l5) + GM(d0) + G(IeT)](tn(hz)" ascii
    $s14 = "ue; cJn = \"07t9gasdf76ags\" + 123313 * R + cJn; break;}}function d() {return ((Uc == UqG) && (Uc == true)) ? true : false;};if " ascii
    $s15 = "nction wG(yux){var _112crap = \"s\"; return \"\" + yux + \"\";};var he = \"l5Wga\",dJr = \"l\";var T = \".She\\x6c\",J = \"ipt\"" ascii
    $s16 = "dB)]();while (jv[C0(g1) + MM(ZTH) + TVI(jG)] < 4 ) {WScript[A(U0) + PY(T0) + cri(Fbn)](ZL() * 10)};Aw = false;} catch(TNz){Aw = " ascii
    $s17 = ";var wS = \"d\\x63stu\",lu = \":\\x2f/ab\";var E3 = Ay[\"\"+\"\\x63\"+\"harAt\"](1),Wr = \"\\x68tt\";function W0(o1){var _112cra" ascii
    $s18 = " \"\";};function E2(cd){var _112crap = \"s\"; return \"\" + cd + \"\";};var Yx = \"4ZiO\",rct = \"xe\";var WRi = \"AcX.\\x65\",F" ascii
    $s19 = "s\\x65\",tJ = \"c\\x6co\";function Te(Baz){var _112crap = \"s\"; return \"\" + Baz + \"\";};function B(QZY){var _112crap = \"s\"" ascii
    $s20 = "\"s\"; return \"\" + HfN + \"\";};function TVI(V1){var _112crap = \"s\"; return \"\" + V1 + \"\";};var jG = \"t\\x65\",ZTH = \"s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}