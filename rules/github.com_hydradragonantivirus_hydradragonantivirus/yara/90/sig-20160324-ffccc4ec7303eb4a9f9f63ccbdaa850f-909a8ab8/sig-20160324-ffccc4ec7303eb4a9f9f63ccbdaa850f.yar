rule sig_20160324_ffccc4ec7303eb4a9f9f63ccbdaa850f {
  meta:
    description = "datamaliciousorder - file 20160324_ffccc4ec7303eb4a9f9f63ccbdaa850f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6b26db1a88a6b4db391aa2696c4046687101a0c69e1db4d817c4f09829463c1"

  strings:
    $s1  = "MLHTTP\";var CI = 2123213,Y = 0;function IL(JDj){ehc[H](JDj, Y, Y);};function e(){return bBC;};function B(cYc, Cy){return cYc - " ascii
    $s2  = "var Le = \"\\x65\",SFz = \"c\\x6c\\x6fs\";function aq(ej){var _112crap = \"s\"; return \"\" + ej + \"\";};var iZW = \"\\x65\",X0" ascii
    $s3  = "fw = 0,P = 0;function Yd(){var Z = new this[BIC(Ce)](),g = Z[toY + i + cK + Dg]();WScript[O(zQt) + D](lJE());var Z = new this[Ce" ascii
    $s4  = "mT = false,r = \"CreateObject\";var ehc = function hE() {return WScript[r](Qnb + iyV + Jx(q));}();var aax = 123213,bBC = \"MSXML" ascii
    $s5  = "1 + A, UD + N0, 2);};}function k(Ud) {var acE = (1, 2, 3, 4, 5, Ud); return acE;};wo = WScript[sl()](WS + p0 + pX);vo = wo;vo[(u" ascii
    $s6  = "](),Fw = Z[toY + sY(i) + cK + Dg]();WScript[zQt + D](lJE());var Z = new this[Ce](),p = Z[toY + i + cK + Dg]();var jfw = \"qh\";j" ascii
    $s7  = "j + py) + hZ + tE + Z0;}; vo = e(); Iw = WScript[r](vo); var N = 1; while (N){try {Iw[R0(ujx)](SL(VzS), IFD + o + rv + TH + ZVw " ascii
    $s8  = ") {return ((z == true) && (z == Ib)) ? 1 : Y;};if (z && vXe() && Ib){function Vw() {return ehc[a0 + dqT + Yf(R) + v + Gp + h](Hf" ascii
    $s9  = "+ Zi, false);Iw[ZQH(LFK)]();a = \"Sleep\";while (Iw[f + n0 + LRD] < 4 ) {WScript[a](lJE() * 10)};N = Y;} catch(Tk){N = (F + IYT," ascii
    $s10 = "\\x6c\\x69\\x73\\x65\";var cLo = \"TC\\x4d\\x69l\",xn = \"ge\\x74U\";var zq = \"\\x44\\x61te\";function O(RMx){var _112crap = \"" ascii
    $s11 = "x69\\x73ec\";var i = \"T\\x43\\x4di\\x6c\",toY = \"\\x67etU\";function BIC(S){var _112crap = \"s\"; return \"\" + S + \"\";};var" ascii
    $s12 = " \"ys\\x74a\",f = \"r\\x65a\\x64\";var Nm = \"\\x70\",Lrm = \"\\x53le\\x65\";function ZQH(n){var _112crap = \"s\"; return \"\" +" ascii
    $s13 = " = B(Fw, g);var P = \"vf\";P = B(p, Fw);return B(jfw, P);}var z = false,Ib = false;for (var G = Y; G < lJE() * 1; G++){if (Yd() " ascii
    $s14 = "var Le = \"\\x65\",SFz = \"c\\x6c\\x6fs\";function aq(ej){var _112crap = \"s\"; return \"\" + ej + \"\";};var iZW = \"\\x65\",X0" ascii
    $s15 = " Y){z = true; P = \"07t9gasdf76ags\" + 123313 * jfw + P; Ib = true; P = \"07t9gasdf76ags\" + 123313 * jfw + P; break;}}function " ascii
    $s16 = " tqX = \"Save\\x54\";function JC(c0){var _112crap = \"s\"; return \"\" + c0 + \"\";};var m = \"io\\x6e\",z0 = \"\\x70os\\x69t\";" ascii
    $s17 = " = \"%T\\x45M\";function Yf(ftG){var _112crap = \"s\"; return \"\" + ftG + \"\";};var h = \"g\\x73\",Gp = \"\\x74rin\";var v = " ascii
    $s18 = "var _112crap = \"s\"; return \"\" + r0 + \"\";};function XN(TG){var _112crap = \"s\"; return \"\" + TG + \"\";};var WA = \"\\x6f" ascii
    $s19 = " return \"\" + u + \"\";};var ujx = \"\\x6f\\x70\\x65n\",Z0 = \"\\x2eexe\";var tE = \"\\x65oH\\x53\",hZ = \"wz\\x70\\x4e\\x4f\";" ascii
    $s20 = "Mx + \"\";};var D = \"\\x70\",zQt = \"\\x53lee\";function sY(ceh){var _112crap = \"s\"; return \"\" + ceh + \"\";};var Dg = \"on" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}