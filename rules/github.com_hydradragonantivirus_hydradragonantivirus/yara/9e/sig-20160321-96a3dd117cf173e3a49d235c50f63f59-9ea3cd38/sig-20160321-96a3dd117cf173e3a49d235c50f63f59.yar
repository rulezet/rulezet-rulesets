rule sig_20160321_96a3dd117cf173e3a49d235c50f63f59 {
  meta:
    description = "datamaliciousorder - file 20160321_96a3dd117cf173e3a49d235c50f63f59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0268bfe333eb9118950b2c5631400d967f909bb288a466d9f6279cf33bb431da"

  strings:
    $x1  = "function Dmmp(Gr){return Gr;};function HfjC(NlB){return NlB;};function KQT(QK){return QK;};var hOCpD = \"uP8xeIku\";var j2 = \"1" ascii
    $s2  = "+ aNn(M) + Dm + (function W(){return P;}()); VRwQz = RXBk(); N = WScript[VIe(w) + (function kn(){return Tx;}()) + BQNT(gGKdB)](V" ascii
    $s3  = "= zM[I + kg(NIU) + WEwE + kr(zpz) + (function J0(){return IhNYL;}()) + xOT + j(K) + mp(v)]();WScript[E(RAl)](T());var zM = new t" ascii
    $s4  = "vDtQ) + (function k0(){return qOFj;}()), false);N[o(IYKxe)]();while (N[GEJW(s) + burs(Se) + w0] < 4 ) {WScript[RAl](T() * 10)};u" ascii
    $s5  = ")]();WScript[(function avgn(){return RAl;}())](T());var zM = new this[(function zmFJ(){return CdN;}()) + Hx(T1) + rE]();var Pju " ascii
    $s6  = "+ sQ(d0) + pKx(Xp) + euW + Vkff;};function Pdgni(Pmh, Bnh){return Pmh - Bnh;};function b(){return w + Tx + (function T0(){return" ascii
    $s7  = "n jigu() {return oYx && R;};if (jigu()){OPdy = xP[ErMD(D) + VSK + (function nFb(){return YtWBt;}()) + A(L) + (function cbhD(){re" ascii
    $s8  = "aD = \"Cr\\x65\";function Bn(kNiSt){return kNiSt;};function aNn(x){return x;};var P = \".exe\";var Dm = \"GP\";var M = \"Lui\\x4" ascii
    $s9  = "YdI = \"\\x6dbjp\";var X = \"Y\\x51\";var f = \"%/\";var UKjF = \"%TEMP\";function ErMD(p0){return p0;};function A(jvwr){return " ascii
    $s10 = "w = false;} catch(e){};}mJEt = WScript[b()](y(tmE) + (function cUzP(){return gq;}()) + zBYYT + dAjaW + (function Tp(){return YoP" ascii
    $s11 = "eturn kfKS;};var gGKdB = \"ct\";var Tx = \"e\\x4fb\\x6ae\";var w = \"C\\x72eat\";var xP = function PtRV() {return WScript[(funct" ascii
    $s12 = "IhNYL = \"e\\x63\";var zpz = \"lis\";var WEwE = \"l\";var NIU = \"Mi\";var I = \"get\";function U(hedue){return hedue;};function" ascii
    $s13 = "return MTn;}()));}();function xxf(WWDs){xP[(function ROiD(){return pvDj;}())](WWDs, 0, 0);};function RXBk(){return nz(p) + ZgJL " ascii
    $s14 = " (function NexxN(){return WEwE;}()) + (function Vnct(){return zpz;}()) + (function WdCmg(){return IhNYL;}()) + xOT + K + yicei(v" ascii
    $s15 = "K) + (function vyGSg(){return v;}())]();var jj = \"Nry\";jj = Pdgni(Pju, ETmbl);var XQF = \"Uzo\";XQF = Pdgni(mSReD, Pju);return" ascii
    $s16 = "his[(function J(){return CdN;}()) + vYwXe(T1) + (function WoJ(){return rE;}())]();var mSReD = zM[(function XKEm(){return I;}()) " ascii
    $s17 = "FR(){return ldHg;}())] = 0;mJEt[Z(V) + TCCEj + (function YXyyF(){return Uz;}())](OPdy, 2 );mJEt[G(yM) + (function X0(){return yz" ascii
    $s18 = "(bzNUC) + AaO(Sn) + B + fQe(MgEx) + (function ccE(){return Pye;}()) + (function R0(){return r;}()) + mx(oGy) + oYx ? Gng(LXz) + " ascii
    $s19 = "){return w;}()) + Tx + gGKdB]((function mNum(){return WjkK;}()) + oc(Lx) + (function bxA(){return GgzLR;}()) + (function NSxR(){" ascii
    $s20 = "+ (function Ecvn(){return NIU;}()) + WEwE + wYa(zpz) + (function uk(){return IhNYL;}()) + (function pJ(){return xOT;}()) + ZKBX(" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}