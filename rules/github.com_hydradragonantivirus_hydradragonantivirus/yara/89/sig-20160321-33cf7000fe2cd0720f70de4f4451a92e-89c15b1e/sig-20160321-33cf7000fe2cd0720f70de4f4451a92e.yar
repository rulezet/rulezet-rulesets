rule sig_20160321_33cf7000fe2cd0720f70de4f4451a92e {
  meta:
    description = "datamaliciousorder - file 20160321_33cf7000fe2cd0720f70de4f4451a92e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a59492674d727b3789599bad57ff59bd7e66fb50bcc5166aae05d092ecb7444"

  strings:
    $x1  = "function K(uUdFm){return uUdFm;};function yedk(kZmi){return kZmi;};function cOF(Tx1){return Tx1;};var JEA = \"6\\x32\";var eEBGt" ascii
    $s2  = "w this[pzT(nwd)]();var r = aIpiy[(function Ri(){return r1;}()) + i + Vrl + YuuWY + ywyq(MvRcZ) + n]();WScript[cdar(eojW) + (func" ascii
    $s3  = " oYD(){return MvRcZ;}()) + (function FKLb(){return n;}())]();WScript[eojW + (function vJ(){return oLib;}())](o());var aIpiy = ne" ascii
    $s4  = "+ (function NSlh(){return TkUdj;}()) + (function Yqlkj(){return oP;}()); ZlA = tx(); fOnie = WScript[Wgp + (function A(){return " ascii
    $s5  = "ction OCNVA(){return O;}()) + kRloG + (function JHQgV(){return NWzbi;}()) + AZirf(Otu) + (function BYAQc(){return oBRSy;}()) + (" ascii
    $s6  = "s(k0) + (function yoNrx(){return TT;}()) + hPXz(IQD);};function DT(zRsp, xZ){return zRsp - xZ;};function UV(){return hSXMT(Wgp) " ascii
    $s7  = " true;LRzB = true;break;}}function ENO() {return VB && LRzB;};if (ENO()){cyV = sE[BRFX + (function zxs(){return Btll;}()) + (fun" ascii
    $s8  = "FQO[\"\\x63\\x68arA\\x74\"](1);var sVTc = \"ec\";var DacDI = \"eObj\";var Wgp = \"Creat\";var sE = function fLTk() {return WScri" ascii
    $s9  = "e(AFNep)] < 4 ) {WScript[eojW + y(oLib)](o() * 10)};Lt = false;} catch(e){};}bHBT = WScript[UV()]((function fNsC(){return XSnJX;" ascii
    $s10 = "n AZirf(ihXhM){return ihXhM;};var b0 = \"ings\";var oBRSy = \"St\\x72\";var Otu = \"\\x74\";var NWzbi = \"\\x65n\";var kRloG = " ascii
    $s11 = "uWY = \"o\\x6e\";var Vrl = \"lise\\x63\";var i = KZns[\"\\x63\\x68arA\\x74\"](2);var r1 = \"get\\x4di\";function bYcrf(hXemx){re" ascii
    $s12 = "function VeKLU(){return b0;}())](cC(tMbe) + EBgIR(X0)) + (function dNqgS(){return YxJvM;}()) + SL(hJEHI) + lPKr(WzZ) + dGIt(b1) " ascii
    $s13 = "tion HADv(){return xYhRo;}()) + (function EnP(){return eh;}()) + (function ZOBd(){return b2;}()) + (function yhP(){return qw;}()" ascii
    $s14 = "o;}()) + (function aDt(){return VL;}())](cyV, 2 );bHBT[Diz(sxny) + NEU(pLGP)]();T(cyV);YnT = \"\" + (function yD(){return LHXA;}" ascii
    $s15 = "}()) + SN(F0) + S(UWPl) + (function xrGde(){return laV;}()) + (function yfP(){return YWj;}()) + VB ? (function f0(){return UE;}(" ascii
    $s16 = ")) + (function QsB(){return u0;}()) + QKVUV(XCYs) : uhUPq + K(aMY) + yedk(eEBGt) + cOF(JEA);}" fullword ascii
    $s17 = " DT(fmb, r);return DT(YnT, HV);}var VB = false;var LRzB = false;for (var WSSY = 0; WSSY < o() * 1; WSSY++){if (LwOp() != 0){VB =" ascii
    $s18 = "+ (function VRpM(){return DacDI;}()) + mPTB(sVTc) + X(qxYGl);};function o(){return 22;};function LwOp(){var aIpiy = new this[bYc" ascii
    $s19 = " AyzRb(){return hzkR;}()), WviyA + ewJm + q2(VF) + (function q3(){return Ye;}()) + (function Ep(){return ZEsks;}()) + p0 + (func" ascii
    $s20 = "), false);fOnie[kvC + z(Zdk)]();while (fOnie[KlK(nJ) + (function aJeL(){return xq;}()) + (function twP(){return nhTA;}()) + xEZu" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}