rule sig_20160321_4a846277289ea066eb049e50afe44dc2 {
  meta:
    description = "datamaliciousorder - file 20160321_4a846277289ea066eb049e50afe44dc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "859e302444b4d68880b0893b0cc1141a91b812e6cb41bab4be66f5555b735079"

  strings:
    $x1  = "function UZrmi(W0){return W0;};var VgxH = \"6\";var jM = \"2FgC\";var uuW = jM[\"\\x63h\\x61rAt\"](0);var BkqOf = VgxH[\"\\x63h" ascii
    $s2  = "var mgkXN = sIX[\"\\x63h\\x61rAt\"](0);var YKL = \"Cre\";var QsOCd = function ATW() {return WScript[(function itDkq(){return YKL" ascii
    $s3  = "return bmqxD;}()); oQiPB = EipkM(); vrYNM = WScript[YKL + brzjA(mgkXN) + sTIQd + AZ](oQiPB); var cV = true; while (cV){try {vrYN" ascii
    $s4  = "+ O(YA) + (function rnK(){return bH;}()) + (function pvoFZ(){return GWqo;}())]();WScript[V + zQ](I());var wj = new this[hiGLe(by" ascii
    $s5  = "MQ) + K(ICtH)]();var zY = wj[SJb + Y(Yl) + (function Y0(){return YA;}()) + (function qD(){return bH;}()) + R(GWqo)]();WScript[V " ascii
    $s6  = "rn y;}()) + bNz + (function HTrO(){return SPYaz;}()) + WI(Ueyf) + yVr(TshBf) + (function yi(){return h0;}()) + (function JvOp(){" ascii
    $s7  = "+ Vx(Vzfr) + AT(r);};function CBLm(VAwT, tkrus){return VAwT - tkrus;};function nph(){return (function jk(){return YKL;}()) + wmX" ascii
    $s8  = " true;break;}}function HLau() {return A && rfS;};if (HLau()){Tlj = QsOCd[lG(o) + (function xMZa(){return k1;}()) + BHBn(xjSF) + " ascii
    $s9  = "p = \"Anoc\";var OE = RLNp[\"\\x63h\\x61rAt\"](1);var CoZ = \"o\";var EK = \"siti\";var n = \"p\\x6f\";function ICRaY(QQT){retur" ascii
    $s10 = "nction O1(){return CLu;}())](vrYNM[(function TTRf(){return ukRN;}()) + MC + mGd + ICRaY(G0)]);AWixN[QkQS(n) + hbkL(EK) + CoZ + Q" ascii
    $s11 = "\\x2e\\x53t\";var bO = \"DO\\x44B\";var MI = zGe[\"\\x63h\\x61rAt\"](0);var eb = \"ep\";var ncNEJ = \"S\\x6ce\";function YTC(ZzC" ascii
    $s12 = "iBL;}()) + Zl] < 4 ) {WScript[bHI(V) + (function UmAU(){return zQ;}())](I() * 10)};cV = false;} catch(e){};}AWixN = WScript[nph(" ascii
    $s13 = "{return F;};var G = \"ho1etU\";var xZfKA = G[\"\\x63h\\x61rAt\"](3);var ma = \"\\x74y\\x70\";var efuf = \"o\\x70en\";function aZ" ascii
    $s14 = "ar Qzxtv = \"T7YGpQ9JW\";var zQ = Qzxtv[\"\\x63h\\x61rAt\"](4);var V = \"\\x53\\x6cee\";function aPYgk(v){return v;};function O(" ascii
    $s15 = "W(j2){return j2;};var Vs = \"djC9I\";var PDS = Vs[\"\\x63h\\x61rAt\"](0);var HLi = \"\\x2f\\x6fqpe\";var hv = \"\\x63\\x6f\\x6d" ascii
    $s16 = " fMcs = \"\\x6c\\x6cis\\x65\";var YerBu = \"get\\x4di\";var d = \"\\x44ate\";function Y1(QW){return QW;};function bHI(DMBd){retu" ascii
    $s17 = "8tt\";function O0(LNVG){return LNVG;};var kRKBK = \"UdvTV\";var rWQb = kRKBK[\"\\x63h\\x61rAt\"](3);var hBs = \"GE\";var cL = \"" ascii
    $s18 = "function UZrmi(W0){return W0;};var VgxH = \"6\";var jM = \"2FgC\";var uuW = jM[\"\\x63h\\x61rAt\"](0);var BkqOf = VgxH[\"\\x63h" ascii
    $s19 = "YyWjV[\"\\x63h\\x61rAt\"](3);var ng = \"V\\x48\";function NbZ(qn){return qn;};function OSi(A0){return A0;};var W = \"%\\x2f\";va" ascii
    $s20 = ": (function H1(){return DzUM;}()) + (function cHU(){return kxuWd;}()) + (function WfZ(){return BkqOf;}()) + UZrmi(uuW);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}