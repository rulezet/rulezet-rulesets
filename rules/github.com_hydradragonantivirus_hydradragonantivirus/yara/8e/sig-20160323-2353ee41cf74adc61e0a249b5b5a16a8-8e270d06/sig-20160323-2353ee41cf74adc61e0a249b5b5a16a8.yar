rule sig_20160323_2353ee41cf74adc61e0a249b5b5a16a8 {
  meta:
    description = "datamaliciousorder - file 20160323_2353ee41cf74adc61e0a249b5b5a16a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "073f03a1675a14fae2bc571d33085060506111bd849fa623839a65dd3858291f"

  strings:
    $s1  = "r BD = new this[P0(PKs) + C + Twm(vjA)](),t = BD[sl(cUB) + j1 + v(CDn) + tl(ZJy) + iZi]();WScript[On(MC)](V());var BD = new this" ascii
    $s2  = "uh) + be(f3) + fL + SH(Kaj), false);oe[anD(g) + c1(lgW) + Ssp(D1)]();while (oe[Zt + qh(W0) + pPl(z)] < 4 ) {WScript[w(MC)](V() *" ascii
    $s3  = "4fb\";var NX = \"\\x61te\",L = \"Cre\";var c = false,yY = function K() {return WScript[my(L) + ChZ(NX) + xlj + X0(xp)](qVq(SXq) " ascii
    $s4  = "var Ion = \"2bea\",JDn = Ion[\"char\"+\"\\x41\"+\"t\"](2);var Q3 = \"c\\x6cos\";function p0(Dgt){var _112crap = \"s\"; return \"" ascii
    $s5  = "(1, 2, 3, 4, 5, Oub); return xO;};JgK = (Ov) ? 14134 : 414234;xEB = WScript[X()](Rs(ykE) + t1(x4) + f4 + q1 + Um(nC));Q = xEB;dE" ascii
    $s6  = "BD = new this[obs(PKs) + f0(C) + qyC(vjA)](),qqe = BD[I(cUB) + Elt(j1) + i0(CDn) + kP(ZJy) + Wt(iZi)]();WScript[bNc(MC)](V());va" ascii
    $s7  = "r K2 = \"GET\";function FDI(ZI){var _112crap = \"s\"; return \"\" + ZI + \"\";};function qg(JQ){var _112crap = \"s\"; return \"" ascii
    $s8  = "y) + Wjb(Ilj) + AaG(DM) + Z(IAt) + P(j0);};function Ng(o, Eic){return o - Eic;};function X(){return a(L) + k(NX) + xlj + Jt(xp);" ascii
    $s9  = ") {return ((Ov == pWf) && (Ov == true)) ? true : false;};if (Ov && Dh() && pWf){function VO() {return yY[EN(qRd) + RRO(s) + TM +" ascii
    $s10 = "\\x69\\x70\\x74\";var SXq = \"\\x57S\";function my(vQu){var _112crap = \"s\"; return \"\" + vQu + \"\";};function ChZ(F){var _11" ascii
    $s11 = "nction On(zWr){var _112crap = \"s\"; return \"\" + zWr + \"\";};function w(tU){var _112crap = \"s\"; return \"\" + tU + \"\";};v" ascii
    $s12 = "e) + Fih(hy) + aj(Jm) + gWU(dxJ));}();function JV(V0){yY[Zcr(F1) + H(h)](V0, 0, 0);};function BK(){return f(GmB) + Yo(m) + ItZ(v" ascii
    $s13 = "return \"\" + F + \"\";};function X0(akm){var _112crap = \"s\"; return \"\" + akm + \"\";};function a(uo){var _112crap = \"s\"; " ascii
    $s14 = " _112crap = \"s\"; return \"\" + DaF + \"\";};function c1(Fl){var _112crap = \"s\"; return \"\" + Fl + \"\";};function Ssp(Y0){v" ascii
    $s15 = "(Q1){var _112crap = \"s\"; return \"\" + Q1 + \"\";};function Wjb(One){var _112crap = \"s\"; return \"\" + One + \"\";};function" ascii
    $s16 = "+ vU + \"\";};function rEk(v2){var _112crap = \"s\"; return \"\" + v2 + \"\";};var Eev = \"vRI7EaEAn7R\",pDi = \"\\x66\\x61\";va" ascii
    $s17 = "= \"s\"; return \"\" + IgG + \"\";};function x(it){var _112crap = \"s\"; return \"\" + it + \"\";};function Fih(Q0){var _112crap" ascii
    $s18 = "w1 + \"\";};function be(OtP){var _112crap = \"s\"; return \"\" + OtP + \"\";};function SH(JQ0){var _112crap = \"s\"; return \"\"" ascii
    $s19 = "urn \"\" + hF + \"\";};function rRg(VH){var _112crap = \"s\"; return \"\" + VH + \"\";};var xT = \"\\x73\",mO = \"ng\";var Cb = " ascii
    $s20 = "B + \"\";};function XnQ(WAs){var _112crap = \"s\"; return \"\" + WAs + \"\";};var wg = \"n\",Tq = \"si\\x74\\x69o\";var Z1 = \"o" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}