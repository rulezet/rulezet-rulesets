rule sig_20160323_08bb3f7b2593d54101ee35665ec405e2 {
  meta:
    description = "datamaliciousorder - file 20160323_08bb3f7b2593d54101ee35665ec405e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f505910a6e89dd5ae0a807dd20283440cee1b0eef1cf110e908b0e148990cbf1"

  strings:
    $s1  = "var VQv = \"\\x65\",i0 = \"\\x63lo\\x73\";function xO0(asV){var _112crap = \"s\"; return \"\" + asV + \"\";};function zAa(oq){va" ascii
    $s2  = "k() {return WScript[ELx + hRg(mdQ) + Egd(QB) + Sj(Aqx)](e(x0) + XBU(qhv) + g + A0(FZm));}();function G(v){C[Bg(P)](v, 0, 0);};fu" ascii
    $s3  = "r v0 = 0,tOS = 0;function Bc(){var GkE = new this[RzQ(ir) + xS(t)](),pM = GkE[HU + h(RT) + EV(dI) + kt + H(Ne)]();WScript[wUC(O)" ascii
    $s4  = "WScript[Mrt(ELx) + b0(mdQ) + mhA(QB) + RhJ(Aqx)](GW); var c = true; while (c){try {S[jZ](nfU(Cvg), lAj(ovN) + Gc(OKZ) + lGW(kg) " ascii
    $s5  = "ue);};}function r(b) {var A = (1, 2, 3, 4, 5, b); return A;};v0 = (jaQ) ? 14134 : 414234;tzS = WScript[D()](Kur + yAl(l) + k5(o)" ascii
    $s6  = " + WY(Cxl)](Vk());var GkE = new this[ir + t](),irX = GkE[w(HU) + TVU(RT) + dI + ZBu(kt) + Ne]();WScript[O + Cxl](Vk());var GkE =" ascii
    $s7  = "ar _112crap = \"s\"; return \"\" + NOU + \"\";};var gsR = \"5aOsidCNLVr\",S0 = \"f\";var gya = \"f\\x61sd\",F1 = gsR[\"c\"+\"\\x" ascii
    $s8  = "O = D0[\"c\"+\"\\x68\"+\"arAt\"](2);function h(U){var _112crap = \"s\"; return \"\" + U + \"\";};function EV(xL){var _112crap = " ascii
    $s9  = "_112crap = \"s\"; return \"\" + EZN + \"\";};var Ne = \"ond\\x73\",kt = \"sec\";var dI = \"lli\",RT = \"TCM\\x69\";var HU = \"ge" ascii
    $s10 = " \"ea\",lx = pTq[\"c\"+\"\\x68\"+\"arAt\"](0);function d(xMN){var _112crap = \"s\"; return \"\" + xMN + \"\";};var YnX = \"d\",s" ascii
    $s11 = "crap = \"s\"; return \"\" + AbU + \"\";};var v2 = \"L3W%Y6mIl\",MF = \"NTWA\";var ut = \"MP%\\x2f\",UA = \"\\x45\";var sG = MF[" ascii
    $s12 = "](1),eF = v2[\"c\"+\"\\x68\"+\"arAt\"](3);function Mpn(q){var _112crap = \"s\"; return \"\" + q + \"\";};function m(Eu){var _112" ascii
    $s13 = "\"typ\",Bi = \"8Un\";var XYA = Bi[\"c\"+\"\\x68\"+\"arAt\"](2),z = \"op\\x65\";function yAl(u3){var _112crap = \"s\"; return \"" ascii
    $s14 = "+ \"\";};function LGv(RFC){var _112crap = \"s\"; return \"\" + RFC + \"\";};var iB = \"wtueCInL\",xO = iB[\"c\"+\"\\x68\"+\"arAt" ascii
    $s15 = "\"+\"\\x68\"+\"arAt\"](4);var N2 = \"a\",qP = \"\\x61fda\\x66\";function p5(u2){var _112crap = \"s\"; return \"\" + u2 + \"\";};" ascii
    $s16 = " = \"s\"; return \"\" + UjO + \"\";};var Cvg = \"GET\";function V0(lLG){var _112crap = \"s\"; return \"\" + lLG + \"\";};var jZ " ascii
    $s17 = "nction M(){return Amo + F(AYN) + N + gBR(Pgy) + p0(pA) + GcQ(Tyn);};function Vfj(ffV, p){return ffV - p;};function D(){return Ar" ascii
    $s18 = "rn ((jaQ == v1) && (jaQ == true)) ? true : false;};if (jaQ && Tdg() && v1){function ar() {return C[Mpn(In) + m(Y) + CU + CS(T) +" ascii
    $s19 = "4)] < 4 ) {WScript[N0(O) + Cxl](Vk() * 10)};c = false;} catch(kK){c = (XIE(I) + Fx(k4), CFI + p5(F1) + gya + W0(S0), qP + N2, tr" ascii
    $s20 = "\\x2el\",aT = ewI[\"c\"+\"\\x68\"+\"arAt\"](0);var PX = \"se\",kg = \"die\";var OKZ = \"\\x70\\x3a//\",ovN = \"htt\";function nf" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}