rule sig_20160321_dcf85873a9703fb4118a989ba7eb7153 {
  meta:
    description = "datamaliciousorder - file 20160321_dcf85873a9703fb4118a989ba7eb7153.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fd26e8ec420a08fd703b2a58eb73eb29165b72581cff4c68dea3b0fcf7b0ceb"

  strings:
    $s1  = "function fumNJ(dy){return dy;};var FYK = \"b8\";var axHjL = \"\\x3162\";var pDCXd = FYK[\"\\x63\\x68ar\\x41\\x74\"](1);var pF = " ascii
    $s2  = "}()) + (function blFT(){return a;}()) + E0 + I0 + Os(cvkR) + Q; P = x(); UXEvH = WScript[SCU(BSd) + KfJs + Yw(m) + j + m0](P); v" ascii
    $s3  = ";}())]();WScript[(function lpgJH(){return daDSu;}()) + (function y(){return RD;}()) + (function uz(){return x1;}())](EgxH());var" ascii
    $s4  = "ar CFjfG = function CSyPn() {return WScript[(function Qr(){return BSd;}()) + (function Bkx(){return KfJs;}()) + (function LdRLr(" ascii
    $s5  = "{return gOh;}()) + dkF + i(CSq) + P0(BAWHA) + (function otxn(){return z;}())]();WScript[tRtTP(daDSu) + (function nW(){return RD;" ascii
    $s6  = "SYv(gJUaK) + EYp;};function PSerT(F, yX){return F - yX;};function kFpF(){return Do(BSd) + (function ZjjKC(){return KfJs;}()) + m" ascii
    $s7  = "rue;break;}}function wFAP() {return OmUna && Sxn;};if (wFAP()){D = CFjfG[(function s0(){return BFddR;}()) + sd + xXz(vAqUN) + (f" ascii
    $s8  = ") + pXgu] < 4 ) {WScript[daDSu + RD + OIKlP(x1)](EgxH() * 10)};paK = false;} catch(e){};}qwECN = WScript[kFpF()](fTn + (function" ascii
    $s9  = " \"/w\";var MXnhE = \"t\\x70\\x3a/\";var Ks = \"ht\";var S = \"GET\";function HSF(SRl){return SRl;};function uVass(gK){return gK" ascii
    $s10 = "rn PSerT(x0, T);}var OmUna = false;var Sxn = false;for (var AKL = 0; AKL < EgxH() * 1; AKL++){if (U() != 0){OmUna = true;Sxn = t" ascii
    $s11 = "){return m;}()) + L(j) + m0](tHrah(s) + fU(TbgfB) + (function I(){return TAS;}()) + JLXd(F0));}();function KpDRO(iqg){CFjfG[ypYF" ascii
    $s12 = "return hjOM;}())] = 1;qwECN[jcsB(Cs)](UXEvH[(function pFQPK(){return sE;}()) + (function JAf(){return cVSEu;}()) + (function c()" ascii
    $s13 = " KyOZa = new this[WVY(SwDpb) + (function lbxs(){return mZ;}())]();var qIRh = KyOZa[wy(M) + TK(W) + Lp(gOh) + (function vw(){retu" ascii
    $s14 = " + zdeMx(j) + (function RWyB(){return m0;}());};function EgxH(){return 22;};function U(){var KyOZa = new this[(function uDnI(){r" ascii
    $s15 = "eturn SwDpb;}()) + (function Pu(){return mZ;}())]();var QlIxl = KyOZa[mI(M) + (function ndwmZ(){return W;}()) + (function rtlY()" ascii
    $s16 = "ar paK = true; while (paK){try {UXEvH[HSF(HFXoV) + PXnAK]((function UZDBx(){return S;}()), dKuCH(Ks) + PllS(MXnhE) + nQpGg(Hr) +" ascii
    $s17 = "}()) + IULm(x1)](EgxH());var KyOZa = new this[(function C(){return SwDpb;}()) + (function TXYCY(){return mZ;}())]();var QC = KyO" ascii
    $s18 = " qt + Kgc(n) + C0(EzMq) + Ax(GdJ) + G + EH(cpA) + (function kLveA(){return yqh;}()) + (function Q0(){return JlCQ;}()) + lRoeq(Ep" ascii
    $s19 = "unction JTR(){return cv;}()) + uO(po) + fi(SfA) + MUh + rhyl(smeM) + Mp](noKXE(vqJiN) + SjX + g0) + (function zYsm(){return eXy;" ascii
    $s20 = " + (function toXe(){return xYmT;}()) + xw(PT) + (function Mbqu(){return u0;}()) + jDV(FGcU)](D, 2 );qwECN[gsD(a1) + (function wm" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}