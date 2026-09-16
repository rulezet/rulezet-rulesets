rule sig_20160321_c86e455e385c74f1ff01735ab6198812 {
  meta:
    description = "datamaliciousorder - file 20160321_c86e455e385c74f1ff01735ab6198812.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d2e007fac2b94d87dd0e1cc9655dca2b79f6eaed9c1739ec9eb0f9dd23ea1f6"

  strings:
    $s1  = "function OvLaN(ZIoR){return ZIoR;};function f1(Sn){return Sn;};var gPbTy = \"62\";var XV = \"\\x381\";var hwo = \"218\\x336\";fu" ascii
    $s2  = "o) + OJQQ + (function BCN(){return DZ;}()) + SwM + Q0]();WScript[lVBLD(I0) + (function wfS(){return hXk;}()) + EA](qro());var ru" ascii
    $s3  = "\"](2);var IJ = \"ate\\x4f\";var BS = \"\\x43r\\x65\";var DRuL = function i() {return WScript[BS + np(IJ) + PQ(Ml) + (function E" ascii
    $s4  = "};}Yd = WScript[d()]((function Lnig(){return ZnFfq;}()) + DdcHJ(yx) + tfnn(OPiy) + (function HNvv(){return Y0;}()));Yd[((functio" ascii
    $s5  = "); iSp = f(); Q = WScript[EMfH(BS) + IJ + (function QedS(){return Ml;}()) + bLNMu(CxMFa)](iSp); var o = true; while (o){try {Q[n" ascii
    $s6  = "KBJv(){return Q0;}())]();WScript[QiCB(I0) + (function dOD(){return hXk;}()) + jWigb(EA)](qro());var ruqG = new this[J(j)]();var " ascii
    $s7  = "ion eo(){return K;}()) + BYnKV + GCdtN(YTs) + fnsU(kT);};function UBX(XsnZH, mETNi){return XsnZH - mETNi;};function d(){return M" ascii
    $s8  = "= true;s = true;break;}}function l() {return wt && s;};if (l()){xcXsh = DRuL[nsR(ERr) + (function aVBeK(){return Fw;}()) + (func" ascii
    $s9  = "RUB = \"\\x63s\";var gGg = \"t\";var CLM = \"/r\";var C0 = \"\\x2f\";var elKq = \"tp:\";var Bnrl = \"\\x68t\";function LD(lo){re" ascii
    $s10 = "())]();while (Q[wbVO(GgwmI) + Sv] < 4 ) {WScript[(function Mulgk(){return I0;}()) + hXk + EA](qro() * 10)};o = false;} catch(e){" ascii
    $s11 = "WWh5MlSwOE\";var Em = ygj[\"ch\\x61rAt\"](5);var AIKAh = \"el\";var sXfue = \"pt\\x2eSh\";var ihSoc = \"W\\x53c\\x72i\";function" ascii
    $s12 = "x44\";var e0 = \"bpTxt\";var U = e0[\"ch\\x61rAt\"](1);var yVuM = \"\\x53lee\";function wbVO(wgGWb){return wgGWb;};var Sv = \"" ascii
    $s13 = "tion EMfH(X){return X;};function bLNMu(FjmI){return FjmI;};var WyxS = \"vVboQL\";var CxMFa = \"\\x6a\\x65ct\";var Ml = WyxS[\"ch" ascii
    $s14 = "(jD){DRuL[(function cKNs(){return RRv;}()) + kLsMh(L)](jD, 0, 0);};function f(){return (function qCeaR(){return Nn;}()) + (funct" ascii
    $s15 = "II + THu](hA + LD(X0), Bnrl + (function sCYYF(){return elKq;}()) + cwxXK(C0) + (function BYBci(){return CLM;}()) + gGg + Yqvu(lR" ascii
    $s16 = "lVoT = ruqG[Vb(qzEfo) + x(OJQQ) + (function YdAW(){return DZ;}()) + hzIi(SwM) + Q0]();var gciS = \"B\";gciS = UBX(RU, A);var w =" ascii
    $s17 = " w0(obU) + (function ny(){return bnDC;}()) + DjhzH + zH(TeX) + (function wkMF(){return Ae;}()) + (function kjIh(){return QES;}()" ascii
    $s18 = "UB) + JU(nS) + nzWpl(ywc) + (function t(){return IfA;}()) + (function H(){return vN;}()), false);Q[(function pGoQ(){return oDs;}" ascii
    $s19 = "tion rQC(){return Ax;}()) + FpRmj(WFQ) + UZS(LJ) + (function fZ(){return I1;}()) + OETc + SulZ + MqgHs(mq)](djlj(j0) + Q1(B0)) +" ascii
    $s20 = "rn CxMFa;}())](pebLa(ihSoc) + (function wHUKt(){return sXfue;}()) + (function D(){return AIKAh;}()) + ow(Em));}();function gqXzr" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}