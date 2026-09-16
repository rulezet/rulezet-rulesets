rule sig_20160323_0ddc00fc36cd8c0bb5d2812ce120c9eb {
  meta:
    description = "datamaliciousorder - file 20160323_0ddc00fc36cd8c0bb5d2812ce120c9eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "294caba35be42f8acae2a8c14c28dd9504b012c86d637e87660238ae163927c2"

  strings:
    $s1  = "function WEW(Y0){var _112crap = \"s\"; return \"\" + Y0 + \"\";};var dAa = \"s\\x65\",B0 = \"c\\x6c\\x6f\";function gNc(Ccs){var" ascii
    $s2  = "{var fgD = (1, 2, 3, 4, 5, e); return fgD;};P = (nk) ? 14134 : 414234;IKp = WScript[hY()](DVE + vSE + j0(SFW) + dE(m4));YRm = IK" ascii
    $s3  = ");var wEB = new this[QBw(rn)](),RxR = wEB[piJ(ke) + bn + E0(jEh) + z0 + bxI(N) + f(De)]();WScript[ZX(R) + vR0(Yf)](Fcq());var wE" ascii
    $s4  = " Mm + \"\";};var vR = \"\\x65\\x63t\",Kc = \"O\\x62j\";var nWA = \"reat\\x65\",oi = \"C\";var PR = false,D = function tCd() {ret" ascii
    $s5  = "ction Tr(){var wEB = new this[ytq(rn)](),LXR = wEB[ke + b(bn) + m1(jEh) + giG(z0) + NK(N) + De]();WScript[vLm(R) + x0(Yf)](Fcq()" ascii
    $s6  = "\\x68\"+\"arAt\"](2),cQi = \"\\x72\\x65\\x61\";var z = u0[\"c\"+\"\\x68\"+\"arAt\"](1);function Iy(Ja){var _112crap = \"s\"; ret" ascii
    $s7  = "n \"\" + IeH + \"\";};function Aj(a0){var _112crap = \"s\"; return \"\" + a0 + \"\";};var JX = \"5LUe1xj6\",AK = JX[\"c\"+\"\\x6" ascii
    $s8  = " return \"\" + v + \"\";};function T(So){var _112crap = \"s\"; return \"\" + So + \"\";};var tBj = \"hvCBpi\",Yf = tBj[\"c\"+\"" ascii
    $s9  = "w[\"c\"+\"\\x68\"+\"arAt\"](0);var VGV = \"\\x68\\x74\\x74\";function C0(qH){var _112crap = \"s\"; return \"\" + qH + \"\";};fun" ascii
    $s10 = "112crap = \"s\"; return \"\" + UJ + \"\";};var C = \"fN8TGhE\",b3 = C[\"c\"+\"\\x68\"+\"arAt\"](3);var TR0 = \"G\\x45\",fck = \"" ascii
    $s11 = " + \"\";};var Lzx = \"asKNOP\",GyH = Lzx[\"c\"+\"\\x68\"+\"arAt\"](0);var e1 = \"afd\\x61f\";function XIs(zIp){var _112crap = \"" ascii
    $s12 = "tion X(){return QJh + Iy(VJV) + iqq(Xf) + yo(wM);};function S(eDc, att){return eDc - att;};function hY(){return UD(oi) + Llm(nWA" ascii
    $s13 = "df76ags\" + 123313 * P + K; Jqt = true; K = \"07t9gasdf76ags\" + 123313 * P + K; break;}}function yiy() {return ((nk == Jqt) && " ascii
    $s14 = " == true)) ? true : false;};if (nk && yiy() && Jqt){function Z() {return D[b0 + tY(Rnh) + zY(v0) + i + n0 + ytP(A) + Q(V3) + iKm" ascii
    $s15 = "XI = \"bPpfwdEc\";var mf = XI[\"c\"+\"\\x68\"+\"arAt\"](5),OC = \"\\x65\\x6e\";var qsV = V4[\"c\"+\"\\x68\"+\"arAt\"](2);functio" ascii
    $s16 = "\",Rpo = \"C\\x7aTh\";var WY = \"\\x329\",UZk = hX[\"c\"+\"\\x68\"+\"arAt\"](5);var rH = \"MP%/\",dgR = \"\\x25TE\";function tY(" ascii
    $s17 = " \"tIuZ\",CcR = B[\"c\"+\"\\x68\"+\"arAt\"](0);var YX = \"\\x65c\",Sgi = \"bj\";var RE = \"t\\x65\\x4f\",b2 = \"Cr\\x65a\";funct" ascii
    $s18 = "t\"](1);var Hrm = \"p\",V5 = \"ty\";var Y = \"hGaogCepS\",IW = \"pe\\x6e\";var gSt = Y[\"c\"+\"\\x68\"+\"arAt\"](3);function j0(" ascii
    $s19 = "r zx = \"ToFil\",D2 = \"\\x76e\";var z4 = \"Sa\";function cMw(mO){var _112crap = \"s\"; return \"\" + mO + \"\";};function BuE(H" ascii
    $s20 = "\"\";};function giG(xC0){var _112crap = \"s\"; return \"\" + xC0 + \"\";};function NK(I){var _112crap = \"s\"; return \"\" + I +" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}