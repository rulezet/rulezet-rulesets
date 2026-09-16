rule sig_20160324_ea80edc24898c413c227812b1b7a1dbe {
  meta:
    description = "datamaliciousorder - file 20160324_ea80edc24898c413c227812b1b7a1dbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13f1898e27ae4ecaa80237e9e12a06f5a85890f2f9b8184ed9666a661ac576f2"

  strings:
    $s1  = "var Aj = \"cl\\x6f\\x73\\x65\";function Cwu(uk){var _112crap = \"s\"; return \"\" + uk + \"\";};var aqQ = \"\\x65\",s = \"ToF\\x" ascii
    $s2  = "VC + RTT](tK());var QZ = new this[B](),nuU = QZ[FRA + PKS + d + BDR]();WScript[VC + TC(RTT)](tK());var QZ = new this[vl(B)](),zo" ascii
    $s3  = "tion tK(){return 22;};var sgo = 0,J = 0;function uZ(){var QZ = new this[a(B)](),GA = QZ[FRA + pkz(PKS) + at(d) + BDR]();WScript[" ascii
    $s4  = "};}function pmT(tH) {var k = (1, 2, 3, 4, 5, tH); return k;};LA = WScript[U()](X + F2 + lMo);QW = LA;QW[(Lp)]();QW[hAZ] = pmT(1)" ascii
    $s5  = "};var BDR = \"co\\x6eds\",d = \"\\x6cise\";var PKS = \"\\x43M\\x69l\",FRA = \"getU\\x54\";function a(vc){var _112crap = \"s\"; r" ascii
    $s6  = "= true; J = \"07t9gasdf76ags\" + 123313 * sgo + J; break;}}function pkh() {return ((y == true) && (y == qie)) ? 1 : TFo;};if (y " ascii
    $s7  = " pkh() && qie){function Uu() {return Y[fW + F + o + K0 + cZ + fJ](UjV + sda(Ta)) + seJ(H) + I + ku + ocr(yL);}; QW = i(); DFb = " ascii
    $s8  = "leep\";while (DFb[yKz(iAt) + bq + D] < 4 ) {WScript[lPt](tK() * 10)};p = TFo;} catch(i0){p = (dot + F1, PX + O1, LoY(Q) + qY, 2)" ascii
    $s9  = "teO\\x62\",jog = \"\\x43rea\";var my = false,Ca = \"CreateObject\";var Y = function j() {return WScript[Ca](wVU + HYw + G + eeg)" ascii
    $s10 = "WScript[Ca](QW); var p = 1; while (p){try {DFb[xDG(Lp)](O, Ty + i2(O0) + E0 + Fpa + lz + ucC + j1, false);DFb[K1(sh)]();lPt = \"" ascii
    $s11 = " = \"ope\\x6e\";var lMo = \"e\\x61m\",F2 = \".\\x53tr\";var X = \"\\x41DOD\\x42\";function LoY(zrg){var _112crap = \"s\"; return" ascii
    $s12 = "+ mFa + \"\";};function at(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};function pTb(p0){var _112crap = \"s\"; return \"" ascii
    $s13 = "rAy){var _112crap = \"s\"; return \"\" + rAy + \"\";};function ocr(L){var _112crap = \"s\"; return \"\" + L + \"\";};var yL = \"" ascii
    $s14 = " _112crap = \"s\"; return \"\" + D0 + \"\";};var D = \"\\x74e\",bq = \"\\x79s\\x74a\";var iAt = \"re\\x61d\",Oy0 = \"\\x70\";var" ascii
    $s15 = " \"\";};function vl(j0){var _112crap = \"s\"; return \"\" + j0 + \"\";};var B = \"\\x44at\\x65\",V = \"R\\x75\\x6e\";var nq = \"" ascii
    $s16 = "(z){var _112crap = \"s\"; return \"\" + z + \"\";};var RTT = \"\\x70\",VC = \"Sl\\x65\\x65\";function pkz(mFa){var _112crap = \"" ascii
    $s17 = "var Ty = \"\\x68ttp\",O = \"\\x47E\\x54\";function xDG(NaD){var _112crap = \"s\"; return \"\" + NaD + \"\";};var Lp = \"\\x6fpen" ascii
    $s18 = ".e\\x78\";var I = \"\\x51b\\x5aTR\",H = \"y\\x33C\\x52Y\";function sda(F0){var _112crap = \"s\"; return \"\" + F0 + \"\";};var T" ascii
    $s19 = "nction K1(ha){var _112crap = \"s\"; return \"\" + ha + \"\";};var sh = \"s\\x65nd\";function i2(hv){var _112crap = \"s\"; return" ascii
    $s20 = "x53ave\",v = \"io\\x6e\";var jb = \"pos\\x69t\";function JrQ(ot){var _112crap = \"s\"; return \"\" + ot + \"\";};function uR(ySX" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}