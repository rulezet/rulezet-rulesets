rule sig_20160321_bf031696e872587f18ff3a8bc8d16549 {
  meta:
    description = "datamaliciousorder - file 20160321_bf031696e872587f18ff3a8bc8d16549.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1102f77bced42d29c870124fa14046edccc10e3a6aa3060633c6de5a5c003576"

  strings:
    $s1  = "function ZgH(irPGp){return irPGp;};function DfJIS(X1){return X1;};var NlvE = \"6FZcb2J\";var rxX = NlvE[\"charAt\"](5);var tgPW " ascii
    $s2  = "i = \"\\x65ate\";var BOznm = \"Cr\";var gO = function Hc() {return WScript[(function Jdpzj(){return BOznm;}()) + Rsl(edaTi) + Ra" ascii
    $s3  = "e){};}vwo = WScript[i()]((function Zhwr(){return t2;}()) + (function m0(){return Mw;}()) + (function DPOvJ(){return xvp;}()) + O" ascii
    $s4  = "+ dLKx(wew) + (function n(){return isy;}()) + XBPMr(WvMBj) + (function J0(){return mdAj;}())]();WScript[(function Ab(){return iq" ascii
    $s5  = "()) + (function Fx(){return hx;}()) + (function G0(){return jwb;}()) + wqT(EUo) + nW(wrQ) + G1(JTem); xHhML = f(); oh = WScript[" ascii
    $s6  = ") + WvMBj + QMpot(mdAj)]();WScript[(function RH(){return iqh;}()) + vKnFk](Yr());var wAJ = new this[Nb(w)]();var hFYVJ = wAJ[(fu" ascii
    $s7  = "Rrj](z(wYuG) + qQwL + GN(QzwV) + IOu(KDQmO));}();function uMEkX(THAfx){gO[Fcy(KMv)](THAfx, 0, 0);};function f(){return raT(J) + " ascii
    $s8  = " WW;}());};function oagIx(dvm, W0){return dvm - W0;};function i(){return B(BOznm) + (function D(){return edaTi;}()) + (function " ascii
    $s9  = "1 + PAu(S) + (function bNzL(){return mkqCt;}()), false);oh[Uy + (function Brz(){return RUnAE;}())]();while (oh[l0(Y) + (function" ascii
    $s10 = " Yr() * 1; jgn++){if (sT() != 0){zajl = true;IkB = true;break;}}function pSIU() {return zajl && IkB;};if (pSIU()){nHL = gO[(func" ascii
    $s11 = "2(B0){return B0;};function PAu(SOL){return SOL;};var hzYGu = \"J:\";var nAF = \"xX.4oHQ\";var F = \"csY\";var MSJD = \"b7JoO4\";" ascii
    $s12 = " CzjWz(){return rU;}()) + Nj(fsx) + pAvq] < 4 ) {WScript[iqh + (function Ag(){return vKnFk;}())](Yr() * 10)};vP = false;} catch(" ascii
    $s13 = "xH[\"charAt\"](4);var c0 = \"Cr\";function ji(oy){return oy;};function wqT(NkvMW){return NkvMW;};function nW(nXxW){return nXxW;}" ascii
    $s14 = "JTxuQ = \"//\\x61\";var RWVbW = hzYGu[\"charAt\"](1);var Da = \"tp\";var NpQY = \"ht\";var wUJZ = \"\\x45T\";var u0 = \"G\";func" ascii
    $s15 = "function ZgH(irPGp){return irPGp;};function DfJIS(X1){return X1;};var NlvE = \"6FZcb2J\";var rxX = NlvE[\"charAt\"](5);var tgPW " ascii
    $s16 = ";};function Nb(ob){return ob;};var w = \"\\x44a\\x74e\";var jbsWO = \"pneC9X7\";var zJlTQ = \"\\x63\\x74\";var T = jbsWO[\"charA" ascii
    $s17 = "a){return Ama;};var oTTq = \"TQjMpiqv\";var vKnFk = oTTq[\"charAt\"](4);var iqh = \"Slee\";function UCkPr(DdR){return DdR;};func" ascii
    $s18 = "\"a\\x73d\";var Gf = \"ose\";var AZipC = \"cl\";function jeY(HF){return HF;};var Sx = \"beUH\";var KoQYU = Sx[\"charAt\"](1);var" ascii
    $s19 = "t\"](3);var pj = \"\\x25\";var t0 = tzL[\"charAt\"](4);var C1 = t[\"charAt\"](3);var kI = \"%TE\";function jx(Q){return Q;};func" ascii
    $s20 = "ion QMpot(Dc){return Dc;};function C0(IVfLs){return IVfLs;};var zbOC = \"o0sm3pka\";var mdAj = zbOC[\"charAt\"](2);var WvMBj = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}