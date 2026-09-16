rule sig_20160321_db41a1e1cafc96e4d5f9bafa88cf85bb {
  meta:
    description = "datamaliciousorder - file 20160321_db41a1e1cafc96e4d5f9bafa88cf85bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c40b2d6828cf865f4e5474f78da1984aa754b3e0a3acf0fd779788ba94265e20"

  strings:
    $s1  = "function J1(UQqlD){return UQqlD;};function ejZR(J2){return J2;};var uy = \"joFWa2\";var N = uy[\"c\\x68a\\x72At\"](5);var jVAGq " ascii
    $s2  = "zaue = QKdKw[kaJq(bugI) + OQ(zTQA) + zd(vJPam) + Z(pXELR) + l]();WScript[LL(zp) + (function D(){return wBNQF;}())](ccfw());var Q" ascii
    $s3  = "bi + o(sv) + YhWA(djV) + S(Ft); YdmMJ = O(); TTv = WScript[GYqG(jkMwW) + tbid + KWL(lt) + (function C(){return uGIU;}())](YdmMJ)" ascii
    $s4  = "KdKw = new this[yyClY(NO)]();var AkI = QKdKw[P(bugI) + zTQA + eB(vJPam) + pXELR + (function emKAq(){return l;}())]();WScript[D0(" ascii
    $s5  = "turn WScript[jkMwW + wlY(tbid) + lt + uGIU]((function L(){return fBAkL;}()) + (function iW(){return wUr;}()) + (function s0(){re" ascii
    $s6  = "Frmm(szdvd, zcLd){return szdvd - zcLd;};function q(){return lWs(jkMwW) + (function BFTdy(){return tbid;}()) + E(lt) + (function " ascii
    $s7  = "ab;}()) + BCgim(ibd)] < 4 ) {WScript[(function b(){return zp;}()) + wBNQF](ccfw() * 10)};bIF = false;} catch(e){};}vNM = WScript" ascii
    $s8  = "O = \"ww\\x77.k\";var rDYB = \"\\x2f/\";var trVp = \"\\x68ttp:\";var q1 = \"\\x47ET\";function Uq(WaIwp){return WaIwp;};function" ascii
    $s9  = "Mlt;};function J(LzXi){return LzXi;};var Jeye = \"aqpwpMe\";var HJjj = \"T\\x50\";var H = \"L\\x48\\x54\";var cyYz = \"\\x2eXM\"" ascii
    $s10 = "()) + yv + z0) + (function op(){return YXxb;}()) + QGSux + (function T(){return A;}()) + (function eLSz(){return TNsU;}()) + MXT" ascii
    $s11 = "(){return lAj;}())](j, 0, 0);};function O(){return y0 + (function Qx(){return lqGlt;}()) + cyYz + mCfOz(H) + J(HJjj);};function " ascii
    $s12 = " oRLL;}()) + Kkv + (function hGd(){return acCcg;}()) + (function kYwu(){return PxGR;}()) + VaW ? (function HvFbZ(){return IGtY;}" ascii
    $s13 = "[q()](XAOWH(Q1) + (function FDK(){return Si;}()) + (function cE(){return m;}()) + (function bnFw(){return hOcRk;}()));vNM[(cIkJa" ascii
    $s14 = "btv(yxNBD) + TTuby(Bmd) + jE + HSu + (function rmo(){return ao;}()) + (function Hjhcw(){return MbOU;}()) + (function S0(){return" ascii
    $s15 = ";}()) + K1] = 0;vNM[(function MUv(){return by;}()) + lip + l0(sR)](IiSLm, 2 );vNM[mE]();Q(IiSLm);lRuys = \"\" + hWGO + R(OWy) + " ascii
    $s16 = " + (function ac(){return DkLN;}()) + aE(pS) + lmu + s1(am) + oQF(cQe) + (function JZNn(){return rRRqM;}()) + (function yIGA(){re" ascii
    $s17 = "(YMuv) + uZM + A0(q0))]();vNM[(function HQIu(){return O0;}()) + kAuwn(yb)] = 1;vNM[BATL(zEJ) + Xwe(vqutv)](TTv[(function Wnf(){r" ascii
    $s18 = "zp) + (function sA(){return wBNQF;}())](ccfw());var QKdKw = new this[(function Crq(){return NO;}())]();var HSR = QKdKw[K0(bugI) " ascii
    $s19 = "; var bIF = true; while (bIF){try {TTv[YMuv + Uq(uZM) + COG(q0)]((function nCVYj(){return q1;}()), H0(trVp) + rDYB + XfZjU(kdgO)" ascii
    $s20 = "ar Sd = \"y\";Sd = Frmm(HSR, AkI);return Frmm(lRuys, Sd);}var VaW = false;var ecG = false;for (var QX = 0; QX < ccfw() * 1; QX++" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}