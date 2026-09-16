rule sig_20160321_fa99407aaadc3b26553c9612a98eed9f {
  meta:
    description = "datamaliciousorder - file 20160321_fa99407aaadc3b26553c9612a98eed9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aff58ef3735deeb6743e7cd9345b85d8b256ce12a78a9deea96145b88f985ce3"

  strings:
    $s1  = "function IF(ycghx){return ycghx;};var YJFV = \"1yua32Q\";var sZ = YJFV[\"\\x63\\x68\\x61\\x72At\"](5);var jTnXV = \"6816\";var Z" ascii
    $s2  = "}H = WScript[Gx()](UmXYh(ovkKw) + (function Jr(){return nbQz;}()) + (function kAL(){return DR;}()) + WNiR + MgIlb(qEkYP) + (func" ascii
    $s3  = " + g + t + (function sD(){return oKnl;}())]();WScript[(function nY(){return sslb;}()) + jRXYb](uAbex());var ruVZ = new this[(fun" ascii
    $s4  = ") + (function JviT(){return g;}()) + Wiu(t) + eQ(oKnl)]();WScript[(function zEc(){return sslb;}()) + (function skm(){return jRXY" ascii
    $s5  = "r O = \"te\";var QTY = \"C\\x72ea\";var Ffe = function tcYp() {return WScript[QTY + O + ceXG(aOL) + O0(ap)]((function yoXPP(){re" ascii
    $s6  = "ction ts(UQ, K){return UQ - K;};function Gx(){return QTY + (function GrO(){return O;}()) + (function AEd(){return aOL;}()) + ap;" ascii
    $s7  = "n qXMIR() {return aB && h;};if (qXMIR()){Yz = Ffe[g0 + (function yd(){return tJE;}()) + I(PdE) + VBu + (function asE(){return LP" ascii
    $s8  = " + W + (function uI(){return fx;}()) + CAJj(YTUt) + njtS(dYL); VNpxJ = b(); UKY = WScript[ppl(QTY) + n(O) + NzdA(aOL) + ap](VNpx" ascii
    $s9  = "n\\x70ap\";var Kp = \".be\";var FmGF = \"\\x2f\\x2f\\x77w\\x77\";var zAU = \"p:\";var FyKg = \"ht\\x74\";function nHEo(QIwEO){re" ascii
    $s10 = "){return lzDY;}()) + myx + (function fb(){return Mbmtb;}())] < 4 ) {WScript[sslb + jRXYb](uAbex() * 10)};Q = false;} catch(e){};" ascii
    $s11 = "s, QmkB);}var aB = false;var h = false;for (var k = 0; k < uAbex() * 1; k++){if (Rklu() != 0){aB = true;h = true;break;}}functio" ascii
    $s12 = "nsMk;}()) + (function ahlsE(){return OHR;}()) + pEvZ(YNP) + vCPvU(nRiT) + dcj + cb(wQDl) + (function FMUnp(){return lAiV;}()) + " ascii
    $s13 = "edOYg + GPADu(dG) + HttsK + HHfDc(e0) + (function TIVo(){return qmBE;}()) + (function I0(){return ZSylH;}()) + aB ? (function XF" ascii
    $s14 = ";H[(function i(){return X0;}()) + ZQW(cpvR)](Yz, 2 );H[lfSgQ(ZXD) + sod(HVZY)]();bPUs(Yz);Bs = \"\" + frjj + (function f(){retur" ascii
    $s15 = "SHG;}()) + raoJ + (function kGLU(){return q;}()) + pF(pZGxg) + kZZu(ARFkw) + XkYM);}();function bPUs(HHHIE){Ffe[piLKs(tTxNl)](HH" ascii
    $s16 = "(){return i0;}()) + H0 : (function iYROr(){return ZWJp;}()) + jTnXV + IF(sZ);}" fullword ascii
    $s17 = "J); var Q = true; while (Q){try {UKY[(function AA(){return ZVuAF;}()) + jUEI(v0)]((function aXjX(){return EndX;}()) + nHEo(XFBA)" ascii
    $s18 = "};function uAbex(){return 22;};function Rklu(){var ruVZ = new this[q0]();var vmcb = ruVZ[UsuA + (function AOmq(){return fokJ;}()" ascii
    $s19 = "()) + (function D0(){return iImIX;}()) + (function dZ(){return lUE;}())]);H[(function jPr(){return BO;}()) + QA(TxTUm) + HX] = 0" ascii
    $s20 = "ction Qsmkb(){return q0;}())]();var SuJW = ruVZ[(function sJ(){return UsuA;}()) + OhkRo(fokJ) + (function ULBz(){return g;}()) +" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}