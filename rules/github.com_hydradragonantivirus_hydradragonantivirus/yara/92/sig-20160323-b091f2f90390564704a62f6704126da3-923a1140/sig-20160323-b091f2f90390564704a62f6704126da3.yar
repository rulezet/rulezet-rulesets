rule sig_20160323_b091f2f90390564704a62f6704126da3 {
  meta:
    description = "datamaliciousorder - file 20160323_b091f2f90390564704a62f6704126da3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0149176be3fffe475f81a4bfe284866f68fdcdb514c948ff21f09613f7d2af62"

  strings:
    $s1  = "= e[YRu(XF) + Bnn + gco(H) + Yqo + IhZ(aIm) + FaX(X0)]();WScript[IK(j0) + kye(Fz) + vCy(uA)](IXK());var e = new this[bDN(A) + df" ascii
    $s2  = "+ PM(H) + Yqo + aIm + bLC(X0)]();WScript[j0 + Kpp(Fz) + ixp(uA)](IXK());var e = new this[ZkT(A) + Fse(ea) + mWn + p0(Cg)](),ztG " ascii
    $s3  = "lbQ) + l2(ctm) + H1(Fn) + YD(l1);}; SSZ = sA(); DD = WScript[JGl(T) + Dv(Cc) + EWg(iV)](SSZ); var LH = true; while (LH){try {DD[" ascii
    $s4  = "2j\";var T = \"Crea\",d = false;var GQu = function nVX() {return WScript[T + mK(Cc) + l(iV)](iF(aH) + F(FM) + cSk + g(PQ) + gj(K" ascii
    $s5  = "function lU(L1){var _112crap = \"s\"; return \"\" + L1 + \"\";};var hiU = \"l\\x6fse\",tZA = \"\\x63\";function CZg(D7){var _112" ascii
    $s6  = "r _112crap = \"s\"; return \"\" + D3 + \"\";};function YD(UJ){var _112crap = \"s\"; return \"\" + UJ + \"\";};var g2 = \"VZbINAu" ascii
    $s7  = "return ((Mrw == u) && (Mrw == true)) ? true : false;};if (Mrw && GbH() && u){function hz() {return GQu[tWQ(b0) + OoI(J0) + tOY(c" ascii
    $s8  = "le (DD[H2(pll) + H3(v0) + uo(vF)] < 4 ) {WScript[Qu(j0) + Fz + OUY(uA)](IXK() * 10)};LH = false;} catch(zSM){LH = (Vl + T1(pb), " ascii
    $s9  = "\\x61\"+\"r\"+\"\\x41\"+\"t\"](0),ut = \"R\\x75\";function iF(Lp){var _112crap = \"s\"; return \"\" + Lp + \"\";};function F(t){" ascii
    $s10 = "n BE(O2){var _112crap = \"s\"; return \"\" + O2 + \"\";};function Jy(lGv){var _112crap = \"s\"; return \"\" + lGv + \"\";};funct" ascii
    $s11 = "function lU(L1){var _112crap = \"s\"; return \"\" + L1 + \"\";};var hiU = \"l\\x6fse\",tZA = \"\\x63\";function CZg(D7){var _112" ascii
    $s12 = "turn \"\" + R + \"\";};function lvV(D4){var _112crap = \"s\"; return \"\" + D4 + \"\";};function k(Ve){var _112crap = \"s\"; ret" ascii
    $s13 = "; return \"\" + RSV + \"\";};function k1(HG){var _112crap = \"s\"; return \"\" + HG + \"\";};function HF(pp){var _112crap = \"s" ascii
    $s14 = " gn(c){var _112crap = \"s\"; return \"\" + c + \"\";};function JGl(OS){var _112crap = \"s\"; return \"\" + OS + \"\";};function " ascii
    $s15 = "var So0 = \"D\\x64\\x6c\",NIz = \"\\x38\";function JDE(beE){var _112crap = \"s\"; return \"\" + beE + \"\";};function Fw(kTZ){va" ascii
    $s16 = "ction Y1(zqk){var _112crap = \"s\"; return \"\" + zqk + \"\";};function V2(Zh){var _112crap = \"s\"; return \"\" + Zh + \"\";};f" ascii
    $s17 = ";}();function CJ(Ze){GQu[ut + mgT](Ze, 0, 0);};function sA(){return rUt(VbF) + ysa(Y) + fzf(X) + AR(txz) + NO(gO);};function Ej(" ascii
    $s18 = "nction pm(hDV){var _112crap = \"s\"; return \"\" + hDV + \"\";};function ueW(xpb){var _112crap = \"s\"; return \"\" + xpb + \"\"" ascii
    $s19 = "\"\";};var Wln = \"T\",xKC = \"G\\x45\";function t0(QP){var _112crap = \"s\"; return \"\" + QP + \"\";};function ep(R){var _112c" ascii
    $s20 = "\"s\"; return \"\" + kTZ + \"\";};var D2 = \"bT%43\",O4 = \"/\";var RX = \"\\x50%\",uU = \"T\\x45M\";var MYd = D2[\"ch\"+\"\\x61" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}