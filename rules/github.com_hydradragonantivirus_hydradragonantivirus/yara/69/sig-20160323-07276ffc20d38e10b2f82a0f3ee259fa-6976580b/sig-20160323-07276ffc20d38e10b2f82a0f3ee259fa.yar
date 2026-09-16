rule sig_20160323_07276ffc20d38e10b2f82a0f3ee259fa {
  meta:
    description = "datamaliciousorder - file 20160323_07276ffc20d38e10b2f82a0f3ee259fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a77e0acbff3de9b2cde7b4877d72a11204c3c2273c3c75b3884730eab92db1d9"

  strings:
    $s1  = "function pYt(Tt){var _112crap = \"s\"; return \"\" + Tt + \"\";};var K3 = \"close\";function ziY(Oyx){var _112crap = \"s\"; retu" ascii
    $s2  = "+ TXS(he), false);Qrk[u1 + S1(o0)]();while (Qrk[spY + Hhj(eME) + JQ(ibj)] < 4 ) {WScript[AG(eOH) + eQ(fU)](Kk() * 10)};ul = fals" ascii
    $s3  = "oJg[zDU + W + p + Fe(lMa) + c(qh) + L0(hB)]();WScript[tep(eOH) + P(fU)](Kk());var oJg = new this[bIe(M) + ta(wI)](),VPf = oJg[vs" ascii
    $s4  = "= \"Cr\\x65a\";var KP = false,S = function x() {return WScript[gPL(IS) + rJs + dC(WN) + pY(vw) + nFd(ziq)](zT(d) + R(qq) + D(l) " ascii
    $s5  = "S = oJg[YW(zDU) + W + p + aE(lMa) + Rn(qh) + R0(hB)]();WScript[r(eOH) + K(fU)](Kk());var oJg = new this[l1(M) + ix(wI)](),nIr = " ascii
    $s6  = "4, 5, jYq); return xZT;};rz = (a) ? 14134 : 414234;N = WScript[Yil()](bE + W1(x0) + c1 + Y1(Po) + g1);Ds = N;MZr = (lTl) ? rz : " ascii
    $s7  = "1);function q2(OL){var _112crap = \"s\"; return \"\" + OL + \"\";};var tr = \"GET\";function Xrq(gEM){var _112crap = \"s\"; retu" ascii
    $s8  = "urn \"\" + W0 + \"\";};var ibj = \"tate\",eME = \"ad\\x79\\x73\";var spY = \"re\";function S1(Ngx){var _112crap = \"s\"; return " ascii
    $s9  = "tion q(cUa, MOC){return cUa - MOC;};function Yil(){return vhS(IS) + rJs + WN + vw + QjH(ziq);};/*@cc_on  @if (@_win32 || @_win64" ascii
    $s10 = "23313 * rz + MZr; lTl = true; MZr = \"07t9gasdf76ags\" + 123313 * rz + MZr; break;}}function PZ() {return ((a == lTl) && (a == t" ascii
    $s11 = "e)) ? true : false;};if (a && PZ() && lTl){function VH() {return S[VN(Ek) + I(wu) + HEU(L1) + fS(Bd) + arv(a0) + Ix(xH0) + tlD(z" ascii
    $s12 = "\\x74\"+\"\"](4),Uro = A[\"charA\"+\"\\x74\"+\"\"](3);var s0 = \"Ru\\x6e\";function zT(hPZ){var _112crap = \"s\"; return \"\" + " ascii
    $s13 = "\\x65\",M = \"Dat\";var s1 = \"c\\x74\",HJP = \"\\x65\\x4fbje\";var g = \"C\\x72\\x65at\";function SaW(okU){var _112crap = \"s\"" ascii
    $s14 = "S\\x6c\";var CBT = \"\\x6fn\\x64s\",CYc = \"is\\x65c\";var A1 = \"ll\",xv = \"CMi\";var ptc = \"getU\\x54\",diF = \"\\x65\";var " ascii
    $s15 = " _112crap = \"s\"; return \"\" + p0 + \"\";};function P(SA){var _112crap = \"s\"; return \"\" + SA + \"\";};function AG(w){var _" ascii
    $s16 = " return \"\" + q1 + \"\";};var FX = \"IkNYFssDL\",hB = FX[\"charA\"+\"\\x74\"+\"\"](5);var qh = \"d\",lMa = \"\\x73econ\";var p " ascii
    $s17 = " r(iBB){var _112crap = \"s\"; return \"\" + iBB + \"\";};function K(pW){var _112crap = \"s\"; return \"\" + pW + \"\";};function" ascii
    $s18 = " A0[\"charA\"+\"\\x74\"+\"\"](3);function YW(vo){var _112crap = \"s\"; return \"\" + vo + \"\";};function aE(kax){var _112crap =" ascii
    $s19 = "x + \"\";};function bM(fDq){var _112crap = \"s\"; return \"\" + fDq + \"\";};var LN = \"\\x46il\\x65\",ys = \"veT\\x6f\";var jaf" ascii
    $s20 = " + \"\";};function l0(lk){var _112crap = \"s\"; return \"\" + lk + \"\";};function cs(Cy){var _112crap = \"s\"; return \"\" + Cy" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}