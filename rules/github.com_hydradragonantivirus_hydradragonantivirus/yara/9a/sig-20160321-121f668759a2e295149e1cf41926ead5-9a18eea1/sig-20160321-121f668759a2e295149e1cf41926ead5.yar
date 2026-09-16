rule sig_20160321_121f668759a2e295149e1cf41926ead5 {
  meta:
    description = "datamaliciousorder - file 20160321_121f668759a2e295149e1cf41926ead5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18b7fafad299e90f69d01b0c76a8b2d8fbb327f0a3c4abc1bb32713a01afdb98"

  strings:
    $s1  = "function v(e0){return e0;};var PJFB = \"9IW972yAYdk\";var vHRx = PJFB[\"\\x63ha\\x72At\"](5);var HGnBV = \"6\";var d1 = \"\\x383" ascii
    $s2  = "nction OBvh(){return Rel;}()) + y]();var bTtpF = f[I(LRljo) + zX(sG) + Rtf(jXhb) + rThbM(SgvQI) + WU]();WScript[Bb(B)](dWtW());v" ascii
    $s3  = " xZ[\"\\x63ha\\x72At\"](5);var bsdED = \"\\x65Ob\";var jC = \"a\\x74\";var q = \"C\\x72e\";var n = function izaq() {return WScri" ascii
    $s4  = "turn sG;}()) + jXhb + (function dJrh(){return SgvQI;}()) + svBar(WU)]();WScript[(function ZjiAN(){return B;}())](dWtW());var f =" ascii
    $s5  = "n H1(){return ZLg;}()); Rb = qlqD(); nURe = WScript[q + (function l(){return jC;}()) + DN(bsdED) + owCK(M) + D(sYjW)](Rb); var m" ascii
    $s6  = "ZCpfT && aGWni;};if (uP()){HDL = n[(function jfKQO(){return Wg;}()) + (function noLZ(){return Jv;}()) + KLb(uWdFT) + W + EA(NH) " ascii
    $s7  = "{return cccq;}())] < 4 ) {WScript[B](dWtW() * 10)};mkFdc = false;} catch(e){};}Qhx = WScript[EcA()]((function UO(){return X;}())" ascii
    $s8  = "x6frk\";var YwqbR = Vb[\"\\x63ha\\x72At\"](0);var BkLsy = \"ht\\x74p:\";function XgJo(lly){return lly;};function k0(ix){return i" ascii
    $s9  = "Wni = false;for (var DJWh = 0; DJWh < dWtW() * 1; DJWh++){if (T() != 0){ZCpfT = true;aGWni = true;break;}}function uP() {return " ascii
    $s10 = " + YxbLn + (function bVM(){return ua;}()) + Q0 + (function B0(){return s;}()));Qhx[(UASoi)]();Qhx[RN + G1(j)] = 1;Qhx[BwuMD + (f" ascii
    $s11 = "on DUpz(){return PdE;}()) + kuX(wioHX) + d(FB) + W0, false);nURe[(function aS(){return SC;}()) + ve(vqKAC) + (function te(){retu" ascii
    $s12 = "unction GS(){return XWH;}())](nURe[zk + Hxxi + (function rv(){return hp;}())]);Qhx[(function PIC(){return hV;}()) + (function wu" ascii
    $s13 = "tion ACS(){return nubEk;}()) + Q(qaW));}();function BLkJa(Qvi){n[CgA + dLTE + (function MSwSw(){return ts;}())](Qvi, 0, 0);};fun" ascii
    $s14 = " new this[TZy(Rel) + (function w(){return y;}())]();var GaZX = f[LRljo + (function JW(){return sG;}()) + M0(jXhb) + ZADut(SgvQI)" ascii
    $s15 = "(function bn(){return M;}()) + (function Ncsv(){return sYjW;}());};function dWtW(){return 22;};function T(){var f = new this[(fu" ascii
    $s16 = "ar f = new this[(function dWBh(){return Rel;}()) + (function f0(){return y;}())]();var pq = f[xeJqQ(LRljo) + (function ilKg(){re" ascii
    $s17 = "HDu(){return uSfgz;}()) + (function gL(){return olbLh;}()) + d0] = 0;Qhx[Jg(ObUe) + kQ(zA)](HDL, 2 );Qhx[(function P0(){return c" ascii
    $s18 = "kFdc = true; while (mkFdc){try {nURe[UASoi](XgJo(Zl) + k0(Jxdp), gBbU(BkLsy) + YwqbR + I0 + Dhw + qmdUT + Ge + DKc(Fb) + (functi" ascii
    $s19 = "n qSRk;}()) + ucR + (function mT(){return Wkz;}()) + Pvqn(hVy) + z0(FVEY) + xG + (function uTUsU(){return Vgj;}()) + hOpg + Pgg(" ascii
    $s20 = "+ p0(nv) + Je(jVcO) + GM]((function G0(){return sV;}()) + (function K(){return lj;}()) + (function k(){return DG;}()) + JbLpk(VG" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}