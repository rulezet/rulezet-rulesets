rule sig_20160321_9c3844ac32e81b9f2f49f7baf819e37e {
  meta:
    description = "datamaliciousorder - file 20160321_9c3844ac32e81b9f2f49f7baf819e37e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d285c8331adaf3f7d0f9c49ab5db755b4de2c888846ec3bac4326002e8c2f209"

  strings:
    $x1  = "function XWI(zzLOE){return zzLOE;};function aO(DPkqk){return DPkqk;};function IFU(y){return y;};var t1 = \"w2PFK\";var oauHU = t" ascii
    $s2  = "turn n0;}()) + XABoG]();var sQ = faplq[UheoZ + RguFr + (function PRlbK(){return NzCm;}()) + vwkHH]();WScript[mypRV(Ydl) + mIYy +" ascii
    $s3  = "f(); Euhh = WScript[bn(B) + iek(aTzXX) + (function F0(){return vN;}()) + nqZHQ](gs); var MwgD = true; while (MwgD){try {Euhh[AgT" ascii
    $s4  = "zCm;}()) + vwkHH]();WScript[Lo(Ydl) + (function BHj(){return mIYy;}()) + mzJZ](CyNU());var faplq = new this[(function oIaMw(){re" ascii
    $s5  = "(n3){return n3;};function SMfD(ad){return ad;};var s = \"ow6\";var q = \"my/pq\";var lyzk = \".com.\";var TB = \"/rtcs\";var xgn" ascii
    $s6  = "j\\x65ct\";var vN = \"b\";var aTzXX = \"\\x74e\\x4f\";var B = \"Crea\";var GXxSJ = function GVJFe() {return WScript[B + aTzXX + " ascii
    $s7  = "+ (function D(){return R;}()) + (function K(){return c;}());};function X(sb, P){return sb - P;};function sTG(){return KuZuG(B) +" ascii
    $s8  = " = true;itESc = true;break;}}function cIbHv() {return V && itESc;};if (cIbHv()){YdMqB = GXxSJ[(function FqA(){return oY;}()) + (" ascii
    $s9  = ") + MO] < 4 ) {WScript[R1(Ydl) + mIYy + (function U(){return mzJZ;}())](CyNU() * 10)};MwgD = false;} catch(e){};}cHm = WScript[s" ascii
    $s10 = "P[\"charAt\"](5);var vgiRb = \"\\x70o\";function ytG(lAf){return lAf;};function SkkE(UU){return UU;};function IrR(X1){return X1;" ascii
    $s11 = " \"\\x41\\x44ODB\";var ZGMYr = \"bBOSO\";var AY = \"ep\";var vQCwO = \"le\";var X0 = ZGMYr[\"charAt\"](3);function PNLS(UMJut){r" ascii
    $s12 = "ction R1(ytMjb){return ytMjb;};var AXpnb = \"pAg9H3\";var mzJZ = AXpnb[\"charAt\"](0);var mIYy = \"\\x65e\";var Ydl = \"Sl\";fun" ascii
    $s13 = "charAt\"](1);var Sec = \"re\";var TkAC = \"nd\";var GCBhe = \"se\";function XCe(gi){return gi;};function K0(K1){return K1;};func" ascii
    $s14 = "unction IIK(i){return i;};var wH = \"cPWIs\";var gX = wH[\"charAt\"](4);var O = \"\\x72\\x69\\x6eg\";var llxAT = \"entSt\";var x" ascii
    $s15 = "turn nsPWy;};var ikicJ = \"oS.XOlE\";var IEYyK = \"am\";var N = \"e\";var ykUOu = \"\\x53\\x74r\";var Qace = ikicJ[\"charAt\"](2" ascii
    $s16 = "(iY){return iY;};function DGO(UacP){return UacP;};var vwkHH = \"ds\";var NzCm = \"econ\";var RguFr = \"illis\";var UheoZ = \"get" ascii
    $s17 = " lmyq = RmC[\"charAt\"](5);var t = \"\\x2eShel\";var iCWt = \"ipt\";var YQCO = \"WSc\\x72\";function KuZuG(F){return F;};functio" ascii
    $s18 = "\"charAt\"](1);var V1 = \"1\\x36\";var lbtd = \"836\\x38\";var joF = \"21\";function NIMC(JW){return JW;};var VuQew = \"\\x61s" ascii
    $s19 = " qd(mzJZ)](CyNU());var faplq = new this[n0 + VHF(XABoG)]();var I = faplq[(function RKQuy(){return UheoZ;}()) + (function giy(){r" ascii
    $s20 = "e);Euhh[GCBhe + TkAC]();while (Euhh[(function LVmnW(){return Sec;}()) + PNLS(yGfy) + (function Ix(){return kwjWv;}()) + YQ(WrOhe" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}