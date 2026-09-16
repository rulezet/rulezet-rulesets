rule sig_20160321_56835624889f5fc66a37316e4e9b0572 {
  meta:
    description = "datamaliciousorder - file 20160321_56835624889f5fc66a37316e4e9b0572.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c7f6e448a01a8a2a545cc217ded76373a0096f67e57192bfa1d5d396be3dcce"

  strings:
    $s1  = "function p0(kvx){return kvx;};var UqFNB = \"62\";var f0 = \"\\x36\\x38\\x31\";var zVp = \"\\x321\\x383\";function EqRdI(WUd){ret" ascii
    $s2  = "ma[R0 + (function Ifwyc(){return PCs;}()) + OHr + KZZuk(boJz) + (function ZFeWm(){return hDfJA;}())] < 4 ) {WScript[G0(dO) + (fu" ascii
    $s3  = ");var PiZ = KnZGb[FWT(R) + qu + ebBAs + (function nRv(){return bxz;}()) + FjHC(CVC) + WUdS(XIUl)]();WScript[dO + Z(q)](F());var " ascii
    $s4  = " + eK(qu) + TXO(ebBAs) + cTU(bxz) + (function TUUeW(){return CVC;}()) + XIUl]();WScript[(function grgTC(){return dO;}()) + dWM(q" ascii
    $s5  = "\";var PEvlD = function z() {return WScript[(function G(){return AjOn;}()) + (function wwNK(){return rMq;}()) + (function SSX(){" ascii
    $s6  = ") + F1(xBcc) + K;};function MuK(HJ, vOG){return HJ - vOG;};function glYqN(){return (function dwnOl(){return AjOn;}()) + JlPwU(rM" ascii
    $s7  = "= true;break;}}function Hicei() {return t && pXC;};if (Hicei()){M = PEvlD[(function tDm(){return vUYwe;}()) + P(E0) + SutUf + (f" ascii
    $s8  = "nction WRkN(){return q;}())](F() * 10)};kDn = false;} catch(e){};}z0 = WScript[glYqN()]((function lR(){return fZ;}()) + M0(hHYI)" ascii
    $s9  = ";var GXsI = \"ds\";var eVTKE = \"\\x63on\";var YP = \"llis\\x65\";var Mk = \"getMi\";var oCnIg = \"Date\";function Z(I0){return " ascii
    $s10 = "unction jXl(){return oc;}()) + i1(OJNWJ) + YQ(T) + RLsk + l0 + hRsFn + t ? (function o0(){return y1;}()) + EqRdI(CpX) : p0(zVp) " ascii
    $s11 = ")]((function i0(){return eWef;}()) + t0) + Kvf(pAGqb) + W(tvo) + (function XqT(){return n;}()) + ISc + iJqNf; XQ = U(); ma = WSc" ascii
    $s12 = "+ (function Ncv(){return f0;}()) + (function NyEH(){return UqFNB;}());}" fullword ascii
    $s13 = " + (function CSPI(){return PqYv;}()) + (function yW(){return Bk;}()) + sYkby(vAaXD));z0[(fg(bR) + OwQC(FTKbu) + hJOWb(f))]();z0[" ascii
    $s14 = "function Sxstn(){return gW;}())](M, 2 );z0[(function Qtk(){return pXQvO;}()) + iWxKl(fS)]();ohmVl(M);qZh = \"\" + (function Gmvv" ascii
    $s15 = "unction X(){return fc;}()) + O(v) + (function LQPc(){return BkVSt;}()) + (function JFhx(){return ZRY;}()) + skPxz(h0) + Ibs(NTiB" ascii
    $s16 = "(function jCk(){return RmsL;}()) + Es(dbZ)] = 1;z0[(function UNw(){return KX;}()) + Wld](ma[kEELS(Nmc) + (function UfHRW(){retur" ascii
    $s17 = "q) + dW(wF) + saIcD(Pr);};function F(){return 22;};function y(){var KnZGb = new this[(function rEuAL(){return V;}()) + PIl(XV)](" ascii
    $s18 = "ript[(function z1(){return AjOn;}()) + (function I(){return rMq;}()) + (function xt(){return wF;}()) + (function F0(){return Pr;" ascii
    $s19 = "cV);return MuK(qZh, y0);}var t = false;var pXC = false;for (var OVnrL = 0; OVnrL < F() * 1; OVnrL++){if (y() != 0){t = true;pXC " ascii
    $s20 = "}())](XQ); var kDn = true; while (kDn){try {ma[bR + rh(FTKbu) + f](zj(ICrX) + llVM(hC), NB(S) + K0 + (function uofkM(){return rR" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}