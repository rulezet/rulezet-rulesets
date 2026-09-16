rule sig_20160324_1070e2ff8632135e8809d5d6947314a4 {
  meta:
    description = "datamaliciousorder - file 20160324_1070e2ff8632135e8809d5d6947314a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2416c5cd7fedca583b64ae40b11dcaa3f342c9ea1569c6117805f71244792d9e"

  strings:
    $s1  = "var PSA = \"clo\\x73e\";function nW(x3){var _112crap = \"s\"; return \"\" + x3 + \"\";};var ed = \"oF\\x69le\",F = \"\\x53aveT\"" ascii
    $s2  = "(E) + lYe(Wr)]();WScript[rF + H(gn)](frJ());var C = new this[Hcu(D)](),x = C[Rt + GTU + E + Wr]();WScript[rF + m(gn)](frJ());var" ascii
    $s3  = "4\";var mv = \"\\x65Obj\\x65\",UNk = \"C\\x72eat\";var Trd = false,DS = \"CreateObject\";var zYk = function gL() {return WScript" ascii
    $s4  = "B + Ly, 2);};}function GT(c) {var wWJ = (1, 2, 3, 4, 5, c); return wWJ;};A = WScript[xaA()](OW + e0(lA) + s0(bHo));U = A;U[(y0(y" ascii
    $s5  = " U = yb(); frj = WScript[DS](U); var k = 1; while (k){try {frj[CQh(ydv)](csn, x1 + x2 + O(FYz) + Lyi + wSQ + z, false);frj[n]();" ascii
    $s6  = "73e\";var Cz = \"\\x54C\\x4di\",QYj = \"get\\x55\";var ahj = \"Dat\\x65\";function H(BY){var _112crap = \"s\"; return \"\" + BY " ascii
    $s7  = "kF + jrK + w);}();var B = 123213,zJn = \"MSXML2.XMLHTTP\";var Kb = 2123213,bz = 0;function l(kDH){zYk[xd](kDH, bz, bz);};functio" ascii
    $s8  = "m)) ? 1 : bz;};if (XB && y() && Lum){function cs() {return zYk[L + rGG + UOU + QH + LM + OJ](il + cpO) + Sk + mDu + aZO + SqE;};" ascii
    $s9  = "23313 * fxp + eb; Lum = true; eb = \"07t9gasdf76ags\" + 123313 * fxp + eb; break;}}function y() {return ((XB == true) && (XB == " ascii
    $s10 = "e = \"Sleep\";while (frj[Ax + gHE(Vh) + f0] < 4 ) {WScript[e](frJ() * 10)};k = bz;} catch(Y){k = (dO + Ugy, IGh(cdg) + WPU(PK), " ascii
    $s11 = "7etUT\";function Hcu(Y0){var _112crap = \"s\"; return \"\" + Y0 + \"\";};var D = \"\\x44\\x61t\\x65\",xd = \"Ru\\x6e\";var rEd =" ascii
    $s12 = " C = new this[D](),lz = C[Rt + WOI(GTU) + E + Wr]();var fxp = \"GU\";fxp = Ht(x, sYM);var eb = \"ZCj\";eb = Ht(lz, x);return Ht(" ascii
    $s13 = "){var _112crap = \"s\"; return \"\" + e1 + \"\";};var B0 = \"t\\x69\\x6fn\",y1 = \"po\\x73i\";var RR = \"\\x42\\x6fd\\x79\",I = " ascii
    $s14 = "ue;  @end@*/if (Trd){function frJ(){return 22;};var fxp = 0,eb = 0;function VB(){var C = new this[D](),sYM = C[TK(Rt) + GTU + Fq" ascii
    $s15 = ";function WOI(GQQ){var _112crap = \"s\"; return \"\" + GQQ + \"\";};var Wr = \"on\\x64\\x73\",E = \"lis\\x65c\";var GTU = \"\\x4" ascii
    $s16 = "var PSA = \"clo\\x73e\";function nW(x3){var _112crap = \"s\"; return \"\" + x3 + \"\";};var ed = \"oF\\x69le\",F = \"\\x53aveT\"" ascii
    $s17 = "turn \"\" + Bua + \"\";};var f0 = \"\\x65\",Vh = \"\\x79stat\";var Ax = \"\\x72\\x65a\\x64\",JgV = \"\\x70\";var v0 = \"S\\x6c" ascii
    $s18 = "ion y0(tjD){var _112crap = \"s\"; return \"\" + tjD + \"\";};var ydv = \"\\x6fpen\",SqE = \".\\x65xe\";var aZO = \"g5\\x4cj\",mD" ascii
    $s19 = "eturn \"\" + qi + \"\";};var PK = \"\\x61sdf\",cdg = \"f\\x61df\";var Ugy = \"\\x61\",dO = \"as\\x64f\";function gHE(Bua){var _1" ascii
    $s20 = " eb);}var XB = false,Lum = false;for (var KFG = bz; KFG < frJ() * 1; KFG++){if (VB() != bz){XB = true; eb = \"07t9gasdf76ags\" +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}