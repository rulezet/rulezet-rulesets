rule sig_20160321_b064bed00f9b22f3ce1670f36c02cf2c {
  meta:
    description = "datamaliciousorder - file 20160321_b064bed00f9b22f3ce1670f36c02cf2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4bbf2662fb230fa2c354409ef4f49aec58e9c1ada4b961fd9ecda7785680c3c"

  strings:
    $s1  = "function zpT(u1){return u1;};function VI(k1){return k1;};var gZE = \"62\";var v0 = \"3681\";var wGIRq = \"18\";var NsZW = \"\\x3" ascii
    $s2  = "WScript[(function IzU(){return o;}()) + YDxsX(SuS) + (function WbwQR(){return nH;}())]((function CyIX(){return XDw;}()) + XTC(E)" ascii
    $s3  = "\"getM\";function x(F){return F;};var ZzRDN = \"ZbFDZLtk\";var d = \"\\x61te\";var bDAGc = ZzRDN[\"\\x63harAt\"](3);var jakV = " ascii
    $s4  = "(){return tbvk;}()) + hojG(yES) + (function rjeJ(){return V;}()) + v(MB)]();WScript[epZ + gUF(bXto) + (function xk(){return DmY;" ascii
    $s5  = "ZkJd(GUr) + QSDU(USp) + nGrJ + IfNH(eftt)] < 4 ) {WScript[(function E0(){return epZ;}()) + (function M(){return bXto;}()) + OK(D" ascii
    $s6  = "function imU(){return V;}()) + MB]();WScript[VWN(epZ) + (function p(){return bXto;}()) + (function GzTq(){return DmY;}())](Tuuf(" ascii
    $s7  = "; lidPV = mYz(); FxWV = WScript[(function qXhYu(){return o;}()) + (function Pj(){return SuS;}()) + (function oHq(){return nH;}()" ascii
    $s8  = "){return uE - h;};function f(){return o + SuS + lV(nH);};function Tuuf(){return 22;};function Ajj(){var UZVZ = new this[(functio" ascii
    $s9  = "eturn hDU && Zn;};if (jAba()){orc = ci[PrFIG(dx) + (function WoEG(){return SGn;}()) + (function gCyPx(){return S;}()) + OWwBU(SL" ascii
    $s10 = "mY)](Tuuf() * 10)};VBp = false;} catch(e){};}aPSk = WScript[f()](XZ(edphI) + xYGqg(jTBW) + (function ojjL(){return oFEr;}()) + (" ascii
    $s11 = "ky\";var cT = \"n\";var jj = KWXzV[\"\\x63harAt\"](5);var tdWk = \"\\x6fp\";function XZ(QsZrb){return QsZrb;};function xYGqg(A0)" ascii
    $s12 = "r CI = \"o\\x73\";var IZ = ws[\"\\x63harAt\"](4);var ul = \"\\x6bj\";var tcdig = \"\\x6c\\x66\";var jrnd = \"a\\x73d\";function " ascii
    $s13 = " = RhOxe[\"\\x63harAt\"](0);function jY(l){return l;};function ktHnE(Y0){return Y0;};function Eogh(BaM){return BaM;};function zO" ascii
    $s14 = "0;};function gd(jkn){return jkn;};function pI(nIMc){return nIMc;};var pjGu = \"hOm\";var QvA = \"m\";var joS = QvA[\"\\x63harAt" ascii
    $s15 = "e = BPOPf[\"\\x63harAt\"](5);var uv = \"j\";var A = \"ateO\\x62\";var aNe = SIDyo[\"\\x63harAt\"](4);var CFZd = \"\\x43\\x72\";f" ascii
    $s16 = " rWG = \"viSb\";var DmY = \"\\x65\\x65\\x70\";var bXto = \"l\";var epZ = rWG[\"\\x63harAt\"](2);function hojG(ezL){return ezL;};" ascii
    $s17 = "4e\";var U = d0[\"\\x63harAt\"](5);function VWN(iugjU){return iugjU;};function gUF(gHK){return gHK;};function OK(gS){return gS;}" ascii
    $s18 = "2fstr\";var tz = cXOKR[\"\\x63harAt\"](5);var sxVjT = U1[\"\\x63harAt\"](4);var j0 = \"\\x74t\";var dAGP = \"h\";function sJY(yY" ascii
    $s19 = "urn yES;}()) + V + XVThJ(MB)]();var AY = \"UXJk\";AY = k(L, CfofT);var TCigj = \"GqYwN\";TCigj = k(pTNU, L);return k(AY, TCigj);" ascii
    $s20 = "));var UZVZ = new this[(function FLdsn(){return bDAGc;}()) + d]();var L = UZVZ[(function mg(){return RFEMc;}()) + (function MSyY" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}