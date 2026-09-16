rule sig_20160324_160798505ad827deaba298aaad386524 {
  meta:
    description = "datamaliciousorder - file 20160324_160798505ad827deaba298aaad386524.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b514a0f72bd01f1b8fc2a476c8b47f833f2d4f95a0017fd2be011ca0bb3a575"

  strings:
    $s1  = "function iqP(iM){var _112crap = \"s\"; return \"\" + iM + \"\";};var E = \"\\x65\",wmT = \"\\x63\\x6cos\";var MRs = \"\\x65\",h " ascii
    $s2  = "e + Qs(qI) + u2 + C + Bce, false);upI[Y0(dg)]();ox = \"Sleep\";while (upI[C0(kk) + Fp + c0] < 4 ) {WScript[ox](S() * 10)};j = cV" ascii
    $s3  = " S(){return 22;};var Y = 0,Xl = 0;function WTu(){var a = new this[F(hK)](),mJ = a[F0 + u + DJL + s0]();WScript[Tqe(Vdb)](S());va" ascii
    $s4  = "r a = new this[Hnq(hK)](),l = a[F0 + u + DJL + s0]();WScript[Vdb](S());var a = new this[hK](),q = a[F0 + u + DJL + s0]();var Y =" ascii
    $s5  = " + K + vzA + l1 + vwP](qH + N) + AW + y + B;}; L = s(); upI = WScript[Up](L); var j = 1; while (j){try {upI[Yq](oE, u1 + Lq + WM" ascii
    $s6  = "var Dqa = \"Cr\\x65a\",WF = false;var Up = \"CreateObject\",Iq = function w() {return WScript[Up](YJ + HCf + i);}();var KE = 123" ascii
    $s7  = "e\\x65p\",s0 = \"nd\\x73\";var DJL = \"isec\\x6f\",u = \"\\x43Mill\";var F0 = \"getU\\x54\";function F(l0){var _112crap = \"s\";" ascii
    $s8  = "l; break;}}function m() {return ((Dyj == true) && (Dyj == g)) ? 1 : cVk;};if (Dyj && m() && g){function DFg() {return Iq[u0 + bX" ascii
    $s9  = "} catch(SAd){j = (ABo + Rw, kvH + Mk, q0 + K0, 2);};}function qrM(Oq) {var Pk = (1, 2, 3, 4, 5, Oq); return Pk;};fwk = WScript[W" ascii
    $s10 = "; iPA++){if (WTu() != cVk){Dyj = true; Xl = \"07t9gasdf76ags\" + 123313 * Y + Xl; g = true; Xl = \"07t9gasdf76ags\" + 123313 * Y" ascii
    $s11 = "ar j0 = \"\\x53a\\x76eT\",K1 = \"t\\x69\\x6f\\x6e\";var VPX = \"\\x70o\\x73\\x69\";function z(cB){var _112crap = \"s\"; return " ascii
    $s12 = "rn \"\" + AV + \"\";};var dg = \"\\x73\\x65nd\";function Qs(eR){var _112crap = \"s\"; return \"\" + eR + \"\";};var Bce = \"\\x6" ascii
    $s13 = "rn \"\" + tX + \"\";};var c0 = \"\\x65\",Fp = \"st\\x61\\x74\";var kk = \"rea\\x64y\",N0 = \"Sle\\x65p\";function Y0(AV){var _11" ascii
    $s14 = "+ \"\";};function Hnq(bpj){var _112crap = \"s\"; return \"\" + bpj + \"\";};var hK = \"Dat\\x65\",Wq = \"Ru\\x6e\";var D = \"HT" ascii
    $s15 = " \"PYQ\";Y = ZhY(l, mJ);var Xl = \"X\";Xl = ZhY(q, l);return ZhY(Y, Xl);}var Dyj = false,g = false;for (var iPA = cVk; iPA < S()" ascii
    $s16 = "function iqP(iM){var _112crap = \"s\"; return \"\" + iM + \"\";};var E = \"\\x65\",wmT = \"\\x63\\x6cos\";var MRs = \"\\x65\",h " ascii
    $s17 = "r Sv = \"\\x64y\",jt = \"n\\x73eBo\";var QI = \"Res\\x70o\";function tV(lh){var _112crap = \"s\"; return \"\" + lh + \"\";};var " ascii
    $s18 = "w0 = \"T\\x43Mi\";var FXf = \"ge\\x74U\",bIt = \"D\\x61\\x74e\";function Tqe(UeU){var _112crap = \"s\"; return \"\" + UeU + \"\"" ascii
    $s19 = "qr = \"MSXML2.XMLHTTP\";var I = 2123213,cVk = 0;function Brm(yCl){Iq[Wq](yCl, cVk, cVk);};function s(){return Kqr;};function ZhY" ascii
    $s20 = "xT, rPd){return wxT - rPd;};function WSm(){return Up;};/*@cc_on  @if (@_win32 || @_win64)    WF = true;  @end@*/if (WF){function" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}