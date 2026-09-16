rule sig_20160321_ca47d53c4f2edbb1e202654f94301304 {
  meta:
    description = "datamaliciousorder - file 20160321_ca47d53c4f2edbb1e202654f94301304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9153a633e76a37e7cf5719c747372f53715ab685159b50615c4549ef1c70d5a"

  strings:
    $s1  = "function V0(DBxug){return DBxug;};var OwgQc = \"\\x362\";var QF = \"6\\x381\";var ElK = \"18\\x33\";var m1 = \"2\";function jKNV" ascii
    $s2  = "n WScript[(function yo(){return APzUn;}()) + xmB(UGOuY) + O0 + CUs + e + MlTUS](O1(dLQgN) + OpnVv + qt(ryWz) + LurW + (function " ascii
    $s3  = "bRm) + (function ROCkh(){return npyM;}())]();WScript[Ft + Cqsq(iJ)](D());var Ikab = new this[U + (function HB(){return XRp;}())]" ascii
    $s4  = "0) + n1(IMvr) + (function GrvrL(){return dx;}()) + (function MyRUb(){return x0;}())] < 4 ) {WScript[Ft + iJ](D() * 10)};wIPH = f" ascii
    $s5  = ")]();var FxZK = Ikab[a0 + Qfkm(LFQ) + K(FYILw) + vbRm + (function V(){return npyM;}())]();WScript[(function UbJ(){return Ft;}())" ascii
    $s6  = ") + (function n(){return GbmQh;}()) + E0(hjsfy) + J1(BrGcJ) + m(kJS) + E; sNJ = ri(); Ypmr = WScript[APzUn + (function v(){retur" ascii
    $s7  = ", dZkuW){return uOX - dZkuW;};function w(){return (function nedKD(){return APzUn;}()) + (function Uxqeu(){return UGOuY;}()) + Dx" ascii
    $s8  = " = 0; fruBq < D() * 1; fruBq++){if (A() != 0){hGj = true;yuMt = true;break;}}function TUK() {return hGj && yuMt;};if (TUK()){noX" ascii
    $s9  = "alse;} catch(e){};}tKtUc = WScript[w()](LZfR(M1) + ys + (function K1(){return JgQPF;}()) + (function Yq(){return etZWW;}()) + (f" ascii
    $s10 = "= 1;tKtUc[(function aajJ(){return NDfHA;}()) + (function r0(){return ESO;}()) + aTEoa(tIjX)](Ypmr[(function eZPS(){return IgQkM;" ascii
    $s11 = "unction d0(){return Oc;}()));tKtUc[(K0(mx) + (function MFlEG(){return aQTY;}()))]();tKtUc[(function LA(){return vq;}()) + ZmtR] " ascii
    $s12 = "CiGtm(){return BvN;}()));}();function X(JzEVY){O[(function J(){return CY;}()) + (function pupA(){return uocp;}())](JzEVY, 0, 0);" ascii
    $s13 = "b0 + (function qXgj(){return oGG;}()) + udduF + (function AW(){return O3;}()) + HIkBo + (function sP(){return akf;}()) + pIntQ +" ascii
    $s14 = "tKtUc[(function WWoSz(){return JpMN;}()) + yVW + (function pA(){return IP;}())](noXkx, 2 );tKtUc[zqN(Bx) + (function qu(){return" ascii
    $s15 = "();var dNdF = Ikab[bWk(a0) + (function thjtv(){return LFQ;}()) + N(FYILw) + vbRm + (function KPmc(){return npyM;}())]();var x = " ascii
    $s16 = " zJd;}())]();X(noXkx);x = \"\" + GR + (function F(){return hFAMt;}()) + uh(LUcG) + (function i0(){return qPt;}()) + (function wk" ascii
    $s17 = " + umJlW(iJ)](D());var Ikab = new this[t(U) + QLfx(XRp)]();var Yfa = Ikab[a0 + (function f(){return LFQ;}()) + myIU(FYILw) + d(v" ascii
    $s18 = "(O0) + CUs + uAX(e) + MlTUS;};function D(){return 22;};function A(){var Ikab = new this[(function D1(){return U;}()) + oYrkG(XRp" ascii
    $s19 = "n UGOuY;}()) + O0 + CUs + Ma(e) + WtQ(MlTUS)](sNJ); var wIPH = true; while (wIPH){try {Ypmr[mx + iWG(aQTY)](CmQ + xmPHH, vJRt + " ascii
    $s20 = "me(){return dFXF;}()) + (function Rr(){return IWKcZ;}())]((function zR(){return HrgWE;}()) + k0 + (function jP(){return Mpj;}())" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}