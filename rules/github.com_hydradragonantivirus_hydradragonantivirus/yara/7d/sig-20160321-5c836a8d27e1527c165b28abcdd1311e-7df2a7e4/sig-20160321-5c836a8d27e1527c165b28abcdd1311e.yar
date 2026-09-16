rule sig_20160321_5c836a8d27e1527c165b28abcdd1311e {
  meta:
    description = "datamaliciousorder - file 20160321_5c836a8d27e1527c165b28abcdd1311e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e9af2a32917583b2a1b5c029763698ed1f74e8570ac7752de2430fddbe67a96"

  strings:
    $s1  = "function UbBNw(G){return G;};function zwXL(nw){return nw;};function ami(EOO){return EOO;};var rnJnp = \"xv2\";var Ylk = \"\\x31" ascii
    $s2  = "Ck(LB) + b; ed = F(); rqV = WScript[hKG(xKiJ) + (function qqq(){return F0;}()) + lEx(CSs)](ed); var dBxN = true; while (dBxN){tr" ascii
    $s3  = "}()) + YY(vhQ) + ZM(ppCxx)]();while (rqV[Gp(qmgPQ) + dPjVa + (function Me(){return YFXz;}())] < 4 ) {WScript[mJ + (function ZPJK" ascii
    $s4  = " + TEJDc(DFJTr)]();WScript[(function pCqMe(){return mJ;}()) + (function vU(){return WZG;}()) + Tmt(R)](g());var Jwur = new this[" ascii
    $s5  = "= \"eOb\";var xKiJ = \"C\\x72\\x65a\\x74\";var p = function I() {return WScript[xKiJ + DAZDT(F0) + EZnDV(CSs)](AgeX(TM) + z + TS" ascii
    $s6  = "ction RLz(JOst, Migt){return JOst - Migt;};function zwkcX(){return LhcX(xKiJ) + Jei(F0) + K(CSs);};function g(){return 22;};func" ascii
    $s7  = "ar kmE = 0; kmE < g() * 1; kmE++){if (X() != 0){xYQQA = true;Qcx = true;break;}}function wNEd() {return xYQQA && Qcx;};if (wNEd(" ascii
    $s8  = "(){return WZG;}()) + (function KYUok(){return R;}())](g() * 10)};dBxN = false;} catch(e){};}d = WScript[zwkcX()]((function h0(){" ascii
    $s9  = "= \"mAto1\";var MTD = ZzDqA[\"\\x63h\\x61rAt\"](0);var LxmK = \"\\x53tre\\x61\";var SoR = \"\\x44B.\";var FkzG = \"\\x41\\x44\\x" ascii
    $s10 = "\";var a = \"18\\x33\\x368\";var U0 = rnJnp[\"\\x63h\\x61rAt\"](2);var gOAey = \"fa\\x73df\";var UB = \"a\\x73\\x64\";function F" ascii
    $s11 = "var TAvM = \"getMi\";var E = \"e\";var K0 = \"D\\x61t\";function quYPV(h){return h;};function Zzx(RTXqx){return RTXqx;};function" ascii
    $s12 = "x){return tDx;};var T = \"SW9i9u\";var Aw = \"wHpV3\";var R = Aw[\"\\x63h\\x61rAt\"](2);var WZG = \"lee\";var mJ = T[\"\\x63h\\x" ascii
    $s13 = "h\\x61rAt\"](3);var QWyX = \"s\\x65\";function mRVfq(zwhid){return zwhid;};function bf(UXiin){return UXiin;};function Drj(zRgh){" ascii
    $s14 = "uY = \"il\";var z0 = \"\\x67etM\";function N(htbxH){return htbxH;};var cTOF = \"vD8\";var lXw = \"\\x61te\";var XD = cTOF[\"\\x6" ascii
    $s15 = "urn gfYU;};function ZM(J){return J;};var btSX = \"LCSnS\";var K1 = \"LCGS1d\";var ppCxx = K1[\"\\x63h\\x61rAt\"](5);var vhQ = bt" ascii
    $s16 = "n zRgh;};function TmK(STA){return STA;};var RAKCd = \"6mruUqJL\";var sRhTx = \"\\x7789cd\";var Bx = RAKCd[\"\\x63h\\x61rAt\"](5)" ascii
    $s17 = " + (function TJRN(){return ZdHFG;}()) + bf(S0) + la + Drj(n) + TmK(qNbVh) + Bx + sRhTx, false);rqV[(function MBRt(){return QWyX;" ascii
    $s18 = "tion qN(){return HtWz;}()) + zVHM(gTQe) + lPTmN(fJId) + (function aaQv(){return hlqEs;}()) + (function p1(){return gP;}());};fun" ascii
    $s19 = ") + FX(iu) + DhAyd + (function Esx(){return Yp;}()) + bf0(hKPLB) + C1(vh) + (function wVK(){return fwsNI;}()) + xYQQA ? (functio" ascii
    $s20 = "n UGmD(){return lXw;}())]();var aFmE = Jwur[yfihF(z0) + (function KnZ(){return VPuY;}()) + (function FpAHt(){return OeX;}()) + w" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}