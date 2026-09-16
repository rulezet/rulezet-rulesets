rule sig_20160321_7f8e5eda2821d17e62d5aae32feaa1a3 {
  meta:
    description = "datamaliciousorder - file 20160321_7f8e5eda2821d17e62d5aae32feaa1a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b20b7e51b20830e77248f1891c006b25730c243179dcddde3c0a87e92f48fb81"

  strings:
    $s1  = "function SX(u){return u;};var k2 = \"OU2aF3y\";var xu = \"6\\x38\\x3162\";var KMa = \"183\";var L0 = k2[\"\\x63ha\\x72At\"](2);v" ascii
    $s2  = "w;}()) + R(I) + hUKbW + (function cgjld(){return n;}()); t = iE(); boqo = WScript[(function bQeea(){return KUE;}()) + (function " ascii
    $s3  = " hvMp;}()) + j(kzL)]();WScript[T(cDz)](ND());var K = new this[(function LU(){return Kx;}())]();var VTI = K[Mv(Qmt) + iBc(dgTvU) " ascii
    $s4  = "+ uLizy(tylCV) + kVCy + (function qac(){return hvMp;}()) + (function NKHLD(){return kzL;}())]();WScript[pns(cDz)](ND());var K = " ascii
    $s5  = "n DQQgx() {return WScript[(function APCK(){return KUE;}()) + (function hfj(){return k;}()) + (function uwQ(){return LrXh;}()) + " ascii
    $s6  = ", false);boqo[igozt(BHc) + Hbp(TWn)]();while (boqo[GxB(EphZb) + BF + mw(m) + (function s(){return IypIP;}())] < 4 ) {WScript[cDz" ascii
    $s7  = "PYq - Vp;};function idRw(){return (function Zw(){return KUE;}()) + (function jy(){return k;}()) + Y(LrXh) + gtjEj;};function ND(" ascii
    $s8  = "eak;}}function EM() {return rt && mUf;};if (EM()){J = zNK[(function vrI(){return gEciB;}()) + (function anQ(){return XT;}()) + (" ascii
    $s9  = "](ND() * 10)};lw = false;} catch(e){};}IJ = WScript[idRw()]((function Eby(){return QrI;}()) + Qvl(Clz) + (function kxBOt(){retur" ascii
    $s10 = "r TsbQ = \"\\x61te\";var Ari = KIIn[\"\\x63ha\\x72At\"](5);function T(DkOX){return DkOX;};function pns(GEto){return GEto;};var c" ascii
    $s11 = "(function Pjpia(){return gtjEj;}())](PviZ + vpHpi + ftO + VJPm(r));}();function OZ(RWXZ){zNK[(function YyaTb(){return Zgw;}())](" ascii
    $s12 = "BQd(){return k;}()) + yLBaD(LrXh) + (function Hmk(){return gtjEj;}())](t); var lw = true; while (lw){try {boqo[PeBj(HJvJ) + B(jP" ascii
    $s13 = "eturn YW;}()) + KR(wDOqZ)) + (function Hy(){return phH;}()) + (function kTkwk(){return h;}()) + VjZ + (function clu(){return IKv" ascii
    $s14 = ";}()) + (function oU(){return VN;}())] = 0;IJ[SW + (function gkN(){return M;}()) + (function fpOzr(){return DIMW;}()) + IJq](J, " ascii
    $s15 = "ine(x) + aZEFb(z0) + gTNZb(yxDK) + (function XZ(){return pT;}()) + (function fhH(){return RqEBT;}()) + (function qZR(){return Am" ascii
    $s16 = "RWXZ, 0, 0);};function iE(){return aQ(PAf) + PrJ + (function AuN(){return OtDh;}()) + cbT(VSft);};function kJ(WPYq, Vp){return W" ascii
    $s17 = " kVCy;}()) + r1(hvMp) + (function IIS(){return kzL;}())]();var W = \"jk\";W = kJ(VTI, A);var nn = \"wzVRb\";nn = kJ(Hmi, VTI);re" ascii
    $s18 = "bsj)]((function YXLh(){return jg;}()), (function eb(){return IECG;}()) + q + (function nw(){return hMrn;}()) + (function XGA(){r" ascii
    $s19 = "2 );IJ[jzxmM + k1(Vhy)]();OZ(J);W = \"\" + (function ULBz(){return yZMcm;}()) + (function OXklI(){return Pqcew;}()) + vGA(pQhw) " ascii
    $s20 = "eturn RmecQ;}()) + YXES(RPDGv) + QlY(pvR) + QEzSe(qhm) + (function XNw(){return IX;}()) + (function TmqdE(){return ahJ;}()) + Sp" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}