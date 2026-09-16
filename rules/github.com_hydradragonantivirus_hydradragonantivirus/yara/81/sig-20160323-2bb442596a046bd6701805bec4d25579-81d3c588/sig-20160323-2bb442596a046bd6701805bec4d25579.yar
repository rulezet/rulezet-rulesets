rule sig_20160323_2bb442596a046bd6701805bec4d25579 {
  meta:
    description = "datamaliciousorder - file 20160323_2bb442596a046bd6701805bec4d25579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da73b06bbc3af2390bdbebf8d607c099a116c3fcb71616a7249419ebf125c31"

  strings:
    $s1  = "function UIx(i2){var _112crap = \"s\"; return \"\" + i2 + \"\";};function c1(zJ){var _112crap = \"s\"; return \"\" + zJ + \"\";}" ascii
    $s2  = "EgP = new this[DOa(eiU) + o0](),s0 = EgP[kl(k) + H0(Fn) + fw + f + aL(H) + lYp(bS)]();WScript[h + o1(Vd)](gRV());var EgP = new t" ascii
    $s3  = "\\x65co\";var f = \"i\\x6cli\",fw = \"CM\";var Fn = \"\\x55T\",k = \"get\";function DOa(nq){var _112crap = \"s\"; return \"\" + " ascii
    $s4  = "x41\"+\"\"+\"\\x74\"+\"\"](2),qG = \"Cr\\x65\";var Py = false,F = function yeH() {return WScript[aW(qG) + tS(P) + Hb(rvR) + SqO(" ascii
    $s5  = "(U) + Ndz(j1);};function IEC(SFh, ND){return SFh - ND;};function yj(){return Xt(qG) + PS(P) + wzc(rvR) + Xv(fU) + Z(B) + AJ;};/*" ascii
    $s6  = "turn ((eAx == N) && (eAx == true)) ? true : false;};if (eAx && xV() && N){function Qe() {return F[Ld + j3 + r(Oez) + W0(MU) + l0" ascii
    $s7  = "Ma(j4) + DLk(V1)] < 4 ) {WScript[h + n(Vd)](gRV() * 10)};sab = false;} catch(xjX){sab = (PS0, iKf(q) + sj + hKd(CBX), HW0(XFP) +" ascii
    $s8  = " NGc(fO), true);};}function nf(Wr) {var RL = (1, 2, 3, 4, 5, Wr); return RL;};BZ = (eAx) ? 14134 : 414234;Q0 = WScript[yj()](ve " ascii
    $s9  = "\\x4dP\\x25\",Rj = \"%\\x54\";function r(jB){var _112crap = \"s\"; return \"\" + jB + \"\";};function W0(IX){var _112crap = \"s" ascii
    $s10 = "_112crap = \"s\"; return \"\" + Pd + \"\";};function Y(KTP){var _112crap = \"s\"; return \"\" + KTP + \"\";};var BsN = \"Snav\"," ascii
    $s11 = "_112crap = \"s\"; return \"\" + Fj + \"\";};function fm(rM){var _112crap = \"s\"; return \"\" + rM + \"\";};var o0 = \"ate\",eiU" ascii
    $s12 = "0){var _112crap = \"s\"; return \"\" + k0 + \"\";};function hKd(EuJ){var _112crap = \"s\"; return \"\" + EuJ + \"\";};var CBX = " ascii
    $s13 = "\"; return \"\" + H2 + \"\";};function NGc(gF){var _112crap = \"s\"; return \"\" + gF + \"\";};var fO = \"fa\",XFP = \"a\\x66da" ascii
    $s14 = "function UIx(i2){var _112crap = \"s\"; return \"\" + i2 + \"\";};function c1(zJ){var _112crap = \"s\"; return \"\" + zJ + \"\";}" ascii
    $s15 = "TY(t){var _112crap = \"s\"; return \"\" + t + \"\";};function Q2(e){var _112crap = \"s\"; return \"\" + e + \"\";};var Oli = \"s" ascii
    $s16 = "\"\" + W + \"\";};function NG(XaB){var _112crap = \"s\"; return \"\" + XaB + \"\";};function sPu(pVa){var _112crap = \"s\"; retu" ascii
    $s17 = ",pP = \"lee\";var GTd = mT[\"ch\"+\"\\x61\"+\"r\"+\"\\x41\"+\"\"+\"\\x74\"+\"\"](2);function eSc(vaE){var _112crap = \"s\"; retu" ascii
    $s18 = "2crap = \"s\"; return \"\" + lv + \"\";};function H0(T0){var _112crap = \"s\"; return \"\" + T0 + \"\";};function aL(isZ){var _1" ascii
    $s19 = "t\";function V(NNP){var _112crap = \"s\"; return \"\" + NNP + \"\";};function ek(O0){var _112crap = \"s\"; return \"\" + O0 + \"" ascii
    $s20 = " IX + \"\";};function l0(LCw){var _112crap = \"s\"; return \"\" + LCw + \"\";};function GNa(g1){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}