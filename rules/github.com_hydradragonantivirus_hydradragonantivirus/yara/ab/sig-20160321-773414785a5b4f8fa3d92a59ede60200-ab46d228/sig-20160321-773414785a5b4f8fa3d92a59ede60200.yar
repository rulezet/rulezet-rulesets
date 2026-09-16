rule sig_20160321_773414785a5b4f8fa3d92a59ede60200 {
  meta:
    description = "datamaliciousorder - file 20160321_773414785a5b4f8fa3d92a59ede60200.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b57d510d468188c426b6c264bd3d64ec66a7e82a8071a1d75abf526b325d06c"

  strings:
    $s1  = "function Gfsy(XvWje){return XvWje;};var S = \"E25\";var UHQ = \"\\x38\\x316\\x32\";var tmQh = \"\\x31836\";var cIHvi = S[\"\\x63" ascii
    $s2  = "n VwKT(){return u;}())]();WScript[(function f(){return Bpli;}()) + zAux(Kfinq) + PSCzd(BnpWW)](iMEH());var rLB = new this[rn(z) " ascii
    $s3  = " Up = deTY[\"\\x63harAt\"](5);var AdQf = \"\\x4d\\x69\\x6cl\";var ZAJw = \"get\";function Jn(y){return y;};function rn(U0){retur" ascii
    $s4  = "eOb\";var a = \"C\\x72ea\";var MkmM = function Uq() {return WScript[(function LL(){return a;}()) + SyJmi + pGJGo(KeGi)](KM + pyB" ascii
    $s5  = ";}()) + Jn(Z0)]();var Tn = rLB[ZAJw + ttO(AdQf) + Up + oXVx(wmS) + JHSHZ + (function kOe(){return DGxz;}()) + mLJY(u)]();WScript" ascii
    $s6  = " kj;}())]();while (Fxuig[(function bI(){return VEoK;}()) + JM(ua) + LKjup] < 4 ) {WScript[(function aTQb(){return Bpli;}()) + KH" ascii
    $s7  = " = WScript[(function xwm(){return a;}()) + (function j(){return SyJmi;}()) + KeGi](w); var LDaKt = true; while (LDaKt){try {Fxui" ascii
    $s8  = ");};function JjCbk(){return cRx(Ms) + ZEyFP(G0) + X(D);};function Z(jfG, IoZY){return jfG - IoZY;};function V0(){return v(a) + S" ascii
    $s9  = "r (var mlT = 0; mlT < iMEH() * 1; mlT++){if (V() != 0){AgZ = true;H = true;break;}}function PgsT() {return AgZ && H;};if (PgsT()" ascii
    $s10 = "\\x53\\x74\\x72e\";var h1 = \"D\\x42\";var xSzOO = mLTg[\"\\x63harAt\"](3);var jjYQm = \"AD\";var WNmS = \"p\";var P = \"S\\x6ce" ascii
    $s11 = "Yl(Kfinq) + XqUS(BnpWW)](iMEH() * 10)};LDaKt = false;} catch(e){};}B = WScript[V0()](jjYQm + xSzOO + WIKri(h1) + (function pBeF(" ascii
    $s12 = "XWeME = \"get\";var qX = \"\\x44\\x61\\x74\\x65\";function AWXZg(dAXk){return dAXk;};function zAux(zKTOM){return zKTOM;};functio" ascii
    $s13 = "\";function s(GVLy){return GVLy;};var gapx = \"xiitUKeh\";var Ma = \"\\x74\\x65\";var wOjOH = gapx[\"\\x63harAt\"](2);var oXOR =" ascii
    $s14 = "ar wamH = \"ty\\x70\\x65\";var iRC = \"op\\x65\\x6e\";function WIKri(f0){return f0;};var mLTg = \"fSwOUF\";var pPQJ = \"\\x61m\"" ascii
    $s15 = "function Gfsy(XvWje){return XvWje;};var S = \"E25\";var UHQ = \"\\x38\\x316\\x32\";var tmQh = \"\\x31836\";var cIHvi = S[\"\\x63" ascii
    $s16 = "ar L0 = HMK[\"\\x63harAt\"](5);var U = \"\\x43re\\x61t\";function cRx(Qrq){return Qrq;};function ZEyFP(DUuR){return DUuR;};funct" ascii
    $s17 = "sY){return sY;};function KHYl(QTZ){return QTZ;};function XqUS(malU){return malU;};var Gp = \"HH4e9p\";var BnpWW = Gp[\"\\x63harA" ascii
    $s18 = "dfK(ke){return ke;};var RX = \"wb\";var mm = \"j4v\";var KVN = RX[\"\\x63harAt\"](0);var kFRPG = \"\\x6fm/ce\";var lNtzP = \"\\x" ascii
    $s19 = "Z + Ctpb(M) + bMmm + QbM](eLBIg(Voxs) + t(y0)) + XL + mLqy + F(NgEqe) + (function Dg(){return w0;}()) + qJRw; w = JjCbk(); Fxuig" ascii
    $s20 = "g[AmrI](cb, ORDX(i0) + (function GeeVX(){return FIhZ;}()) + pm + cdfK(F0) + (function rHTTq(){return W;}()) + (function yV(){ret" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}