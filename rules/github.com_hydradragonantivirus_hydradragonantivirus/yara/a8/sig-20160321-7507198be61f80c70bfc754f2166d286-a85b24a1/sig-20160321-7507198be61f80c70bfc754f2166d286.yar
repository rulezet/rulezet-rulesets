rule sig_20160321_7507198be61f80c70bfc754f2166d286 {
  meta:
    description = "datamaliciousorder - file 20160321_7507198be61f80c70bfc754f2166d286.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13317c9cf47b5bc65ed26545ebdf3c473c40566b26054df3445002a33cee893a"

  strings:
    $s1  = "function mKwI(vej){return vej;};var rzwi = \"\\x362\";var D = \"1\";var I2 = \"36\\x38\";var LYR = \"2\\x31\\x38\";function V(Vs" ascii
    $s2  = "\\x74\"](5);var mO = \"eOb\\x6a\\x65\";var ncPM = \"\\x61\\x74\";var YOlo = \"\\x43re\";var h = function rEt() {return WScript[E" ascii
    $s3  = "vKAi[lAQ(j0) + fE(lsa) + qRHrr + j1]();WScript[(function y(){return I;}()) + PY(CP) + AiSn](XaJA());var vKAi = new this[(functio" ascii
    $s4  = "lXwKU + eazI(KzuXv) + M0(an); WkFI = CyT(); ai = WScript[(function EYH(){return YOlo;}()) + (function no(){return ncPM;}()) + vE" ascii
    $s5  = "n Z0(){return j1;}())]();WScript[I + pR(CP) + g0(AiSn)](XaJA());var vKAi = new this[Lz(w) + (function ol(){return v;}())]();var " ascii
    $s6  = "){return rJ;}()) + WiW + hRgZW(hlda)] < 4 ) {WScript[(function pXWr(){return I;}()) + (function FYy(){return CP;}()) + AiSn](XaJ" ascii
    $s7  = "HH + (function cKfDB(){return uJZ;}()) + US(psAx) + (function L(){return VyzUZ;}());};function gYW(AB, ofaCf){return AB - ofaCf;" ascii
    $s8  = ";}}function tbH() {return r && REZ;};if (tbH()){gm = h[(function jcp(){return qfm;}()) + (function AGWt(){return XwdR;}()) + (fu" ascii
    $s9  = "A() * 10)};CSgt = false;} catch(e){};}AI = WScript[Qn()](Ri(hHNZ) + sl(X1) + (function s(){return ev;}()));AI[(J(qAVwi) + (funct" ascii
    $s10 = "\";var lsa = \"\\x69\\x6c\";var j0 = \"getM\";function iy(KCE){return KCE;};function Lz(grN){return grN;};var v = \"te\";var w =" ascii
    $s11 = "X = vKAi[ypoiG(j0) + AdT(lsa) + lbmui(qRHrr) + lGv(j1)]();var mkga = \"j\";mkga = gYW(tr, Kc);var U = \"AulI\";U = gYW(X, tr);re" ascii
    $s12 = "+ (function upj(){return PUFo;}())](A(WqoZR) + xVEGm(ogfG)) + Klh(gGhH) + n(k0) + (function HSlh(){return Wj;}()) + Azomy(U1) + " ascii
    $s13 = "ion uOq(){return xSx;}()))]();AI[QWgao(Um) + lqo(xzPoo)] = 1;AI[cBt + (function qcp(){return YME;}()) + (function PiZp(){return " ascii
    $s14 = "y(mO) + YY + (function f(){return fVC;}())](WkFI); var CSgt = true; while (CSgt){try {ai[(function mE(){return qAVwi;}()) + (fun" ascii
    $s15 = ";AI[gn(SvFG)]();eqwsN(gm);mkga = \"\" + LwxT + (function WhyG(){return X2;}()) + E(mGKHF) + T(BQsgK) + (function bFqzK(){return " ascii
    $s16 = "+ (function yoM(){return Epk;}()) + bmTho + Qu(aSEKI) + (function nQVKN(){return Cli;}())] = 0;AI[v1 + JYkWy + QIu + f0](gm, 2 )" ascii
    $s17 = "n HtZ(){return w;}()) + (function vIS(){return v;}())]();var tr = vKAi[(function Z(){return j0;}()) + lsa + hk(qRHrr) + (functio" ascii
    $s18 = " gYW(mkga, U);}var r = false;var REZ = false;for (var xq = 0; xq < XaJA() * 1; xq++){if (USVru() != 0){r = true;REZ = true;break" ascii
    $s19 = "function kX(){return ncPM;}()) + mO + am(YY) + ALwY(fVC)]((function HqdVr(){return aWuRE;}()) + (function Kfv(){return YYh;}()) " ascii
    $s20 = "};function Qn(){return (function jpmdE(){return YOlo;}()) + (function dU(){return ncPM;}()) + M(mO) + (function d(){return YY;}(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}