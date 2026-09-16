rule sig_20160321_19ba988db01a35988f098af842f422c6 {
  meta:
    description = "datamaliciousorder - file 20160321_19ba988db01a35988f098af842f422c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57591d2c6d1796f1cc0be692c556992120a5dae45745830aa917c8ae11842308"

  strings:
    $x1  = "function qYCA(wvP){return wvP;};function nhxx(VlrXQ){return VlrXQ;};function qR(YQkxH){return YQkxH;};var GsHT = \"\\x31\\x362\"" ascii
    $s2  = "O() {return WScript[(function zvO(){return Yl;}()) + mQECm(IyeM) + (function GW(){return lq;}()) + (function xTuK(){return tHL;}" ascii
    $s3  = ") + CcETH(eHyV) + TM + (function ZCs(){return SuFc;}())]();WScript[DJ + (function H(){return zPUNY;}())](dMh());var Zb = new thi" ascii
    $s4  = "turn EAn;}()) + (function SYmOZ(){return NQcM;}()) + (function COP(){return eHyV;}()) + FnjT(TM) + SuFc]();WScript[t(DJ) + (func" ascii
    $s5  = "P(NtLlf) + cIs(WEbvz); aVIZZ = Egwd(); mT = WScript[Yl + IyeM + OHj(lq) + (function g(){return tHL;}()) + (function aDih(){retur" ascii
    $s6  = "wKF - vY;};function b(){return Yl + IyeM + oGOd(lq) + XKe(tHL) + lVeY(lxa) + (function CpEQs(){return rf;}()) + P;};function dMh" ascii
    $s7  = " eYpVW() {return f && zUxnl;};if (eYpVW()){gWOg = lYRa[(function M(){return DDbB;}()) + Nmv + meflV(DrIBA) + (function Uimf(){re" ascii
    $s8  = "dprb = \"/\";var YySBq = \"TEMP%\";var RQVS = \"%\";function meflV(kkE){return kkE;};function va(A){return A;};function cNvLR(N)" ascii
    $s9  = "Db;}()) + cwNZ(PZ)] < 4 ) {WScript[yKaHU(DJ) + zPUNY](dMh() * 10)};S = false;} catch(e){};}vRF = WScript[b()](z + LAZ(P1) + kFRi" ascii
    $s10 = ";var EZo = \"4qwEdlRLyPA\";var jPv = EZo[\"c\\x68arAt\"](5);var nnkZ = \"Shel\";var Ai = \"pt.\";var ViNnd = \"WS\\x63ri\";funct" ascii
    $s11 = "ng(UME){return UME;};var YkpF = \"rPxWDP\";var Ho = YkpF[\"c\\x68arAt\"](1);var c = \"\\x54\";var HwEt = \"\\x58M\\x4cHT\";var M" ascii
    $s12 = "ar NQkf = \"\\x74ion\";var rMyU = F[\"c\\x68arAt\"](4);var UcM = \"\\x70o\\x73\";function u1(kpblO){return kpblO;};var QDSIA = " ascii
    $s13 = "d\";var QZ = \"\\x67e\";function hecn(bAqBv){return bAqBv;};var zmPW = \"H2eeemRz\";var YI = zmPW[\"c\\x68arAt\"](3);var Yzl = " ascii
    $s14 = "Ri(zd){return zd;};function Xx(GNA){return GNA;};var nvl = \"02D0mB8Im\";var GVrMq = nvl[\"c\\x68arAt\"](4);var qMDA = \"\\x65a" ascii
    $s15 = "= zB[\"c\\x68arAt\"](4);var FCEj = \"Cr\";function vP(hw){return hw;};function UYo(D){return D;};function u(dS){return dS;};func" ascii
    $s16 = "Hd[\"c\\x68arAt\"](2);var tHL = \"\\x65Obj\";var lq = zfHl[\"c\\x68arAt\"](1);var IyeM = \"\\x65a\";var Yl = \"\\x43\\x72\";var " ascii
    $s17 = "\"\\x65nd\";var kAc = obSzN[\"c\\x68arAt\"](1);function LsIW(w){return w;};function a0(YNt){return YNt;};function iN(gfFNy){retu" ascii
    $s18 = "tion k(){return zPUNY;}())](dMh());var Zb = new this[Yzl + (function EHhV(){return YI;}())]();var lta = Zb[QZ + EAn + dOqZO(NQcM" ascii
    $s19 = "s[(function GLBb(){return Yzl;}()) + hecn(YI)]();var NZhm = Zb[(function pqX(){return QZ;}()) + ZSDaS(EAn) + NQcM + eHyV + mPWx(" ascii
    $s20 = "(qMDA) + Xx(GVrMq));vRF[(a + STPsr)]();vRF[vnhmf(yHhI) + W0] = 1;vRF[xx(QRW) + (function vZ(){return zE;}())](mT[kM + kNf + u1(Q" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}