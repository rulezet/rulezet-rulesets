rule sig_20160321_2528f4ccc90c2b01a2141ae167daf7d1 {
  meta:
    description = "datamaliciousorder - file 20160321_2528f4ccc90c2b01a2141ae167daf7d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e1b34ce6a94b5b25fe27ccce7a2097222528079898ec596f2527fd980e92410"

  strings:
    $s1  = "var wQ = \"81\\x362\";var Ylmf = \"21\\x3836\";function GTW(zrofM){return zrofM;};var mW = \"sd\\x66\";var uIgb = \"as\\x64fa\";" ascii
    $s2  = "}()) + OrSG(Pj); NL = wT(); Wr = WScript[(function Qwsp(){return oWvy;}()) + oP + (function Jq(){return AN;}()) + oZpor(jqiR)](N" ascii
    $s3  = " s[zvDF(yxXK) + l + (function zRqUs(){return j;}()) + Mkx + (function Ju(){return Wtfx;}()) + jVMo(isjvl) + QdA]();WScript[DXyI(" ascii
    $s4  = " + (function x(){return l;}()) + j + hqU(Mkx) + (function uoUNK(){return Wtfx;}()) + tQ(isjvl) + Fc(QdA)]();WScript[zU + (functi" ascii
    $s5  = "(){return fDlFZ;}());};function Eml(Yu, D){return Yu - D;};function A(){return Q0(oWvy) + p(oP) + (function uepYX(){return AN;}(" ascii
    $s6  = "){xvvuK = true;ZQOf = true;break;}}function w() {return xvvuK && ZQOf;};if (w()){VTyLR = ZQupw[qBYME(yKDQR) + zKYu(PNejI) + FmhV" ascii
    $s7  = "cBL;};var jqiR = \"e\\x63\\x74\";var AN = \"Ob\\x6a\";var oP = \"reat\\x65\";var oWvy = \"\\x43\";var ZQupw = function r() {retu" ascii
    $s8  = "] < 4 ) {WScript[bBxqf(zU) + KuAGX](V() * 10)};Q = false;} catch(e){};}pWn = WScript[A()](qB(ZXGF) + TdxOt + FLvI(JTmQ) + (funct" ascii
    $s9  = "1;};function OrSG(AfbKw){return AfbKw;};var vhqg = \"MNU4.3HJt\";var Pj = \"exe\";var IeWTw = vhqg[\"\\x63harAt\"](4);var XIh = " ascii
    $s10 = "turn jIk;};var V2 = \"wXwwt6g3\";var L = \"\\x65\";var p0 = V2[\"\\x63harAt\"](4);var GIm = \"dyst\\x61\";var cMK = \"r\\x65\\x6" ascii
    $s11 = "d\";var JTmQ = \"D\\x42.\\x53t\";var TdxOt = i2[\"\\x63harAt\"](5);var ZXGF = \"AD\";var DQ = \"e\\x70\";var H = \"Sl\\x65\";fun" ascii
    $s12 = ";function QDEV(O){return O;};var hwG = \"O17on\";var Z = \"pen\";var gXS = hwG[\"\\x63harAt\"](3);var aVqs = \"ject\";var TRa = " ascii
    $s13 = "= \"\\x6c\";var l = \"\\x65t\\x4d\\x69\";var yxXK = N[\"\\x63harAt\"](2);function i(NA){return NA;};var wbYWw = \"\\x61\\x74e\";" ascii
    $s14 = "ADTD1\";var YIE = \"\\x50%/\";var uezrD = \"TEM\";var ukko = Mf[\"\\x63harAt\"](2);function qBYME(jzm){return jzm;};function zKY" ascii
    $s15 = "P;}()) + (function AxEQ(){return wvO;}())] = 1;pWn[(function xDOLS(){return imdwL;}()) + hOl](Wr[ExCN(zZvq) + UoDCw(VfRY) + nrl " ascii
    $s16 = "+ (function p1(){return n;}())]);pWn[xeQp(rjavf) + dwKLx(Swd) + (function ouc(){return rZi;}())] = 0;pWn[hDuw(kP) + (function tl" ascii
    $s17 = "pj(){return JWGTD;}()) + (function TUQ(){return TuZyE;}())](VTyLR, 2 );pWn[dSmeQ(pNF) + mn(Grbg)]();P(VTyLR);kWM = \"\" + (funct" ascii
    $s18 = "L); var Q = true; while (Q){try {Wr[QDEV(gXS) + (function e(){return Z;}())]((function qWP(){return oovZq;}()) + qWhy, R(C1) + U" ascii
    $s19 = "o(jrb) + V1, false);Wr[yavgY(uavqt)]();while (Wr[(function v0(){return cMK;}()) + (function WXYgF(){return GIm;}()) + p0 + ig(L)" ascii
    $s20 = " + (function k(){return Mkx;}()) + Wtfx + Omg(isjvl) + hEMb(QdA)]();var kWM = \"TGG\";kWM = Eml(oAWLY, ulbS);var BpqGw = \"guoK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}