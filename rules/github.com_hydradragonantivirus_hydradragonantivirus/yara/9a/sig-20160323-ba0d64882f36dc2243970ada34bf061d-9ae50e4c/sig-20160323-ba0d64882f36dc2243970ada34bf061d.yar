rule sig_20160323_ba0d64882f36dc2243970ada34bf061d {
  meta:
    description = "datamaliciousorder - file 20160323_ba0d64882f36dc2243970ada34bf061d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0e13a92b5c77217eb1acf80fa6849604e9174e725bc859052bc4fe68fbe1c86"

  strings:
    $s1  = "function bV(yE){var _112crap = \"s\"; return \"\" + yE + \"\";};function M0(Wb){var _112crap = \"s\"; return \"\" + Wb + \"\";};" ascii
    $s2  = "5, rc); return zaK;};uIQ = (sT) ? 14134 : 414234;K = WScript[C()](eum + Rj(upk) + j0 + Fnq(oE));Q = K;e = (Ve) ? uIQ : e;Q[(sv(n" ascii
    $s3  = "alse);N[WMg(g) + anC(ip)]();while (N[ql(eiF) + eNO + yL(qfN) + mTF(eL)] < 4 ) {WScript[tY(OjC) + kdV(U)](pSe() * 10)};CCo = fals" ascii
    $s4  = "0(yvP) + L0](),jH = oUa[u1 + eI(GP) + L1 + Ge(A) + nX + Rn(bOC) + tC(Bo)]();WScript[OjC + O(U)](pSe());var oUa = new this[Y(yvP)" ascii
    $s5  = " + xHt(L0)](),QFg = oUa[u1 + i(GP) + L1 + A + Cs(nX) + taM(bOC) + Bo]();WScript[sEX(OjC) + b(U)](pSe());var oUa = new this[uO(yv" ascii
    $s6  = "(Az + Jm(P)) + S2(oC) + Rn0(SR) + Sl(H0) + YD;}; Q = OE(); N = WScript[r + wC(WM) + r0(Nb)](Q); var CCo = true; while (CCo){try " ascii
    $s7  = ";var Nb = \"c\\x74\",WM = \"\\x65Ob\\x6a\\x65\";var r = \"C\\x72eat\",Te = false;var bB = function YEL() {return WScript[yb(r) +" ascii
    $s8  = "(NkS) + CgE(Gm) + oT + dd(MG) + gDb(u);};function Cw(An, Fr){return An - Fr;};function C(){return r + WM + Nb;};/*@cc_on  @if (@" ascii
    $s9  = "(sT == true)) ? true : false;};if (sT && SQ() && Ve){function Vl() {return bB[Qm + O0(dh) + LK + Z0(x) + C1(wT) + Gu + Rvn + Uk]" ascii
    $s10 = "asdf76ags\" + 123313 * uIQ + e; Ve = true; e = \"07t9gasdf76ags\" + 123313 * uIQ + e; break;}}function SQ() {return ((sT == Ve) " ascii
    $s11 = "](5),yyG = \"/t\\x69r\\x65\";var w = \"tt\\x70:\\x2f\",N1 = SlO[\"char\"+\"\\x41\"+\"t\"](3);var o0 = \"GET\";function UnP(wf){v" ascii
    $s12 = "x6ae\";var cE = \"\\x74\\x65O\",UnE = \"rea\";var Ox = o[\"char\"+\"\\x41\"+\"t\"](5);function lon(N0){var _112crap = \"s\"; ret" ascii
    $s13 = "\" + agM + \"\";};function Sl(AAG){var _112crap = \"s\"; return \"\" + AAG + \"\";};var YD = \"x\\x65\",H0 = \"S\\x59E\\x2ee\";v" ascii
    $s14 = " return \"\" + eZl + \"\";};function QKU(C0){var _112crap = \"s\"; return \"\" + C0 + \"\";};var Bo = \"c\\x6fnd\\x73\",bOC = \"" ascii
    $s15 = "73tat\";var eNO = Cfp[\"char\"+\"\\x41\"+\"t\"](2),eiF = \"r\\x65a\";function WMg(sVw){var _112crap = \"s\"; return \"\" + sVw +" ascii
    $s16 = "x73\",A = \"\\x6c\";var L1 = \"C\\x4dil\",GP = \"T\";var u1 = \"g\\x65tU\";function u0(k){var _112crap = \"s\"; return \"\" + k " ascii
    $s17 = "mz + \"\";};function Ge(NTB){var _112crap = \"s\"; return \"\" + NTB + \"\";};function Rn(Z){var _112crap = \"s\"; return \"\" +" ascii
    $s18 = "r dx = \"Sa\\x76e\";function h1(L2){var _112crap = \"s\"; return \"\" + L2 + \"\";};function UNr(iU){var _112crap = \"s\"; retur" ascii
    $s19 = "var _112crap = \"s\"; return \"\" + Tzx + \"\";};function taM(vfF){var _112crap = \"s\"; return \"\" + vfF + \"\";};function Uj(" ascii
    $s20 = "12crap = \"s\"; return \"\" + drz + \"\";};function Z0(kru){var _112crap = \"s\"; return \"\" + kru + \"\";};function C1(fZE){va" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}