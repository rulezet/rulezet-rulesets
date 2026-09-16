rule sig_20160324_5f385f2f6753d5055dbcfbf4da4f32dc {
  meta:
    description = "datamaliciousorder - file 20160324_5f385f2f6753d5055dbcfbf4da4f32dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57a7aa9749c9c5ed62c4d40b017397ed19bd83e26d5e17adf44ce3f33ee6c990"

  strings:
    $s1  = "function Vdr(z1){var _112crap = \"s\"; return \"\" + z1 + \"\";};var E = \"clo\\x73e\";function fey(Ed0){var _112crap = \"s\"; r" ascii
    $s2  = "\",Re = function mL() {return WScript[XmB](lR + lm + m(SYG) + cf);}();var BMP = 123213,DK = \"MSXML2.XMLHTTP\";var wjH = 2123213" ascii
    $s3  = " oIM(T) + kKn]();WScript[Y(Ef) + PKo](XvI());var l = new this[C](),Giq = l[HCC(sJR) + hZc + T + kKn]();var x = \"OxZ\";x = M(cpw" ascii
    $s4  = "var l = new this[C](),r = l[sJR + hZc + T + kKn]();WScript[P(Ef) + IDq(PKo)](XvI());var l = new this[C](),cpw = l[sJR + a(hZc) +" ascii
    $s5  = "Z = \"//\\x68\\x75d\",sl = \"h\\x74\\x74p:\";var jn = \"G\\x45T\";function Bs(ccD){var _112crap = \"s\"; return \"\" + ccD + \"" ascii
    $s6  = "(os + JLu) + P0(z0) + VV + mH(GO);}; CyW = TG(); Fu = WScript[XmB](CyW); var Ji = 1; while (Ji){try {Fu[Bs(s)](jn, sl + LvT(Z) +" ascii
    $s7  = "){Ji = (kJR + ZK(qc), g + ijh, wE + BGb, 2);};}function LtL(LR) {var bw = (1, 2, 3, 4, 5, LR); return bw;};dbF = WScript[i()](wI" ascii
    $s8  = "= 0;function X(ATy){Re[B0(Vc)](ATy, d, d);};function TG(){return DK;};function M(xJk, j){return xJk - j;};function i(){return Xm" ascii
    $s9  = "urn ((M0 == true) && (M0 == H)) ? 1 : d;};if (M0 && CXl() && H){function N() {return Re[SZf(QXW) + xS + pbJ + kcu + vL(t) + zjz]" ascii
    $s10 = " wX + ju + lu(MQ) + qK, false);Fu[T0]();e = \"Sleep\";while (Fu[P1 + tj(w) + jsm] < 4 ) {WScript[e](XvI() * 10)};Ji = d;} catch(" ascii
    $s11 = "\\x70en\";function P0(i0){var _112crap = \"s\"; return \"\" + i0 + \"\";};function mH(R){var _112crap = \"s\"; return \"\" + R +" ascii
    $s12 = "function Vdr(z1){var _112crap = \"s\"; return \"\" + z1 + \"\";};var E = \"clo\\x73e\";function fey(Ed0){var _112crap = \"s\"; r" ascii
    $s13 = " = true; Ed = \"07t9gasdf76ags\" + 123313 * x + Ed; H = true; Ed = \"07t9gasdf76ags\" + 123313 * x + Ed; break;}}function CXl() " ascii
    $s14 = "ar P1 = \"re\\x61dy\",a0 = \"Sl\\x65\\x65p\";var T0 = \"\\x73end\";function LvT(A0){var _112crap = \"s\"; return \"\" + A0 + \"" ascii
    $s15 = ";};var qc = \"\\x61\",kJR = \"a\\x73df\";function tj(ll){var _112crap = \"s\"; return \"\" + ll + \"\";};var jsm = \"\\x65\",w =" ascii
    $s16 = "; return \"\" + Qu + \"\";};var km = \"d\\x79\",IVf = \"\\x6es\\x65\\x42\\x6f\";var v = \"\\x52esp\\x6f\",MSx = \"w\\x72ite\";va" ascii
    $s17 = " = \"\\x6fpen\";function wIb(L0){var _112crap = \"s\"; return \"\" + L0 + \"\";};function uf(wXq){var _112crap = \"s\"; return " ascii
    $s18 = "H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};var qK = \"\\x6bad\",MQ = \"\\x6b39s\";var ju = \"\\x2e\\x63\\x6f\\x6d/\",wX" ascii
    $s19 = "ion HCC(Xen){var _112crap = \"s\"; return \"\" + Xen + \"\";};var kKn = \"\\x6e\\x64\\x73\",T = \"i\\x73\\x65co\";var hZc = \"C" ascii
    $s20 = "Ed0 + \"\";};var Wv = \"\\x6fFil\\x65\",Gb = \"S\\x61\\x76eT\";var Kuy = \"\\x69\\x6fn\",xi = \"p\\x6fs\\x69t\";function L1(Qu){" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}