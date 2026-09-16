rule sig_20160321_634fa6b4f98f0e1b45ef9fd65c93810f {
  meta:
    description = "datamaliciousorder - file 20160321_634fa6b4f98f0e1b45ef9fd65c93810f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd721c80788ac2d9576ecd68663c40faad18a9c2c8765c0d6c0d01074e4c99"

  strings:
    $s1  = "RDQcL + hKyd]();WScript[vXWK + (function aH(){return L;}())](cSeK());var wmHwy = new this[(function JkDi(){return ka;}())]();var" ascii
    $s2  = ") + (function DEy(){return RDQcL;}()) + (function u0(){return hKyd;}())]();WScript[(function q0(){return vXWK;}()) + L0(L)](cSeK" ascii
    $s3  = "function oiUmD(JW){return JW;};function NKH(M0){return M0;};function zTT(UAczw){return UAczw;};function b2(dZUAG){return dZUAG;}" ascii
    $s4  = "()); c = xbJN(); NEW = WScript[H0 + sv + (function ZM(){return h;}())](c); var KGarL = true; while (KGarL){try {NEW[(function lX" ascii
    $s5  = "{return Eb;};var h = \"j\\x65ct\";var sv = \"\\x61\\x74eOb\";var H0 = \"\\x43\\x72\\x65\";var gMo = function GIJ() {return WScri" ascii
    $s6  = ") + (function EzBm(){return qy;}()) + W0(L1)] < 4 ) {WScript[TFm(vXWK) + (function U(){return L;}())](cSeK() * 10)};KGarL = fals" ascii
    $s7  = " + OLDK(oBShc) + vj(vrn);};function fXQVQ(eQYh, mWX){return eQYh - mWX;};function xL(){return H0 + dY(sv) + h;};function cSeK(){" ascii
    $s8  = "e;} catch(e){};}OR = WScript[xL()]((function G0(){return hwLg;}()) + (function UZgj(){return GZ;}()) + (function uZWB(){return M" ascii
    $s9  = ";}()));OR[((function atE(){return oWel;}()) + y(nvXt) + (function sGLq(){return hjQV;}()))]();OR[wt(bKJj) + X(j)] = 1;OR[kzZq + " ascii
    $s10 = "= \"\" + awMO(I) + gMVgk + zkS(Yv) + (function r(){return y0;}()) + cBSn + XKgbN(VRehe) + s(ge) + MrntP(i) + (function tp(){retu" ascii
    $s11 = "());var wmHwy = new this[hnpvj(ka)]();var H = wmHwy[(function TLS(){return rz;}()) + (function g(){return f;}()) + tUBh(kdNq) + " ascii
    $s12 = "return CMzLY;}()) + (function shrJK(){return Tmzz;}()) + zhh(jIGj) : oiUmD(gSh) + NKH(PiGvI) + zTT(s0) + b2(YbMq);}" fullword ascii
    $s13 = "eturn oeYUP;}()));}();function HbC(m){gMo[vV(LyP) + pJQ](m, 0, 0);};function xbJN(){return (function jMJN(){return Wq;}()) + LmK" ascii
    $s14 = "(sv) + h]((function wNpjS(){return Xf;}()) + (function za(){return eHC;}()) + (function kQKTG(){return H1;}()) + (function P(){r" ascii
    $s15 = ") + iZ(IQjXs) + pxTO(w), false);NEW[(function TVqJ(){return bfls;}())]();while (NEW[mlxa(Mkfea) + (function a0(){return YuUD;}()" ascii
    $s16 = "= \"vwEW\";Oov = fXQVQ(CWN, H);return fXQVQ(nyDd, Oov);}var t = false;var Bhgsk = false;for (var ivZof = 0; ivZof < cSeK() * 1; " ascii
    $s17 = "(){return oWel;}()) + (function B(){return nvXt;}()) + nexyF(hjQV)](Xe(rvOO) + C0(MlmE), uWyg(uvpbz) + XDt + oiFqg + (function B" ascii
    $s18 = " wmwP;}()) + dpKZC(wESS) + (function tk(){return k;}()) + (function WThVf(){return G1;}()) + KNE(sAWjt) + t ? (function VEQQF(){" ascii
    $s19 = "urn sAhG;}()) + (function AoO(){return hT;}()) + (function DN(){return rhq;}())](UsJ + (function W(){return FCBQt;}()) + nPJ) + " ascii
    $s20 = " CWN = wmHwy[(function uPYe(){return rz;}()) + f0(f) + kdNq + RDQcL + atl(hKyd)]();var nyDd = \"q\";nyDd = fXQVQ(H, nQMk);var Oo" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}