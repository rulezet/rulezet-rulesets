rule sig_20160323_19e96cf1f441d795e7df754a1db3e47c {
  meta:
    description = "datamaliciousorder - file 20160323_19e96cf1f441d795e7df754a1db3e47c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8180c433fc3290f3470388e5c3fe5ff6092e2702bcddc14a10f823a8dca2953"

  strings:
    $s1  = "= WScript[eWV(C) + c + BBF(km) + sNa + DkW(vUY)](u); var h = true; while (h){try {Tv[gN(EN) + K0(kub)](Ly(eqQ) + UY(KCU) + iJ(x1" ascii
    $s2  = "(AJ) + j0(PRJ) + XL + aK(OnC) + Yo(fj) + L0(D) + aq(FZm) + zF(d0)]();WScript[IQ(oV) + aP(Rod)](Qz());var QjS = new this[E0 + q2(" ascii
    $s3  = " \"\\x43re\\x61\";var UmB = false,DUE = function Zq() {return WScript[V(C) + HG(c) + F(km) + zdk(sNa) + pR(vUY)](K(O) + jM(V0) +" ascii
    $s4  = " + So0(mx) + r0(H1), true);};}function l(yN) {var PI = (1, 2, 3, 4, 5, yN); return PI;};Co = (mL) ? 14134 : 414234;MRT = WScript" ascii
    $s5  = "function Q0(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};var ULP = \"o\\x73e\",W0 = \"cl\";function klv(v0){var _112crap " ascii
    $s6  = "ction hYU() {return ((mL == HpA) && (mL == true)) ? true : false;};if (mL && hYU() && HpA){function m() {return DUE[mqU(Udc) + W" ascii
    $s7  = "!= 0){mL = true; oNt = \"07t9gasdf76ags\" + 123313 * Co + oNt; HpA = true; oNt = \"07t9gasdf76ags\" + 123313 * Co + oNt; break;}" ascii
    $s8  = " true;  @end@*/if (UmB){function Qz(){return 22;};var Co = 0,oNt = 0;function nG(){var QjS = new this[E0 + Cn(j)](),wfI = QjS[Ie" ascii
    $s9  = "this[Q(E0) + j](),X = QjS[AJ + SW(PRJ) + XL + ps(OnC) + du(fj) + j1(D) + KM(FZm) + a(d0)]();var Co = \"kUD\";Co = Lww(Eg, wfI);v" ascii
    $s10 = "Ua)] < 4 ) {WScript[fu(oV) + Rod](Qz() * 10)};h = false;} catch(T){h = (JBL(sIu) + RT, wCI(Qt) + r(kN) + du0 + Lih(YNB), H2(AIK)" ascii
    $s11 = "12crap = \"s\"; return \"\" + t0 + \"\";};function ps(c0){var _112crap = \"s\"; return \"\" + c0 + \"\";};function du(Kk){var _1" ascii
    $s12 = "\",F1 = \"n\";var xA = \"ope\";function q4(L6){var _112crap = \"s\"; return \"\" + L6 + \"\";};function xu(Jxh){var _112crap = " ascii
    $s13 = "), AKS + o3(jXO) + gq(x2) + zD(WGK) + sh(Ue) + E2(M1) + Jn(cla) + T0 + y0(aYK), false);Tv[KT(g1)]();while (Tv[iQ + KN(L4) + Hn(z" ascii
    $s14 = "rn \"\" + v0 + \"\";};var J0 = \"ile\",wYd = \"e\\x54oF\";var zb = \"Sav\";function fWS(Eo){var _112crap = \"s\"; return \"\" + " ascii
    $s15 = "mqU(oc){var _112crap = \"s\"; return \"\" + oc + \"\";};function QP(Bdc){var _112crap = \"s\"; return \"\" + Bdc + \"\";};functi" ascii
    $s16 = "nction gN(Em){var _112crap = \"s\"; return \"\" + Em + \"\";};function K0(E1){var _112crap = \"s\"; return \"\" + E1 + \"\";};fu" ascii
    $s17 = "{var _112crap = \"s\"; return \"\" + Gp + \"\";};var x = \"eS\",vUY = \"ect\";var sNa = \"Obj\",km = x[\"cha\"+\"\\x72\"+\"At\"]" ascii
    $s18 = "unction Ie(Z){var _112crap = \"s\"; return \"\" + Z + \"\";};function j0(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};fun" ascii
    $s19 = "ar _112crap = \"s\"; return \"\" + Rqi + \"\";};function HG(E){var _112crap = \"s\"; return \"\" + E + \"\";};function F(jQD){va" ascii
    $s20 = "1){var _112crap = \"s\"; return \"\" + X1 + \"\";};var kub = \"en\",EN = \"o\\x70\";var qyC = \"ec\\x74\",EEn = \"j\";var ew = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}