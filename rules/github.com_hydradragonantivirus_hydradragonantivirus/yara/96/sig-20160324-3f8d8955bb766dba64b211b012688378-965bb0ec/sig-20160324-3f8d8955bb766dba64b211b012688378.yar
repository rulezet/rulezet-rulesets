rule sig_20160324_3f8d8955bb766dba64b211b012688378 {
  meta:
    description = "datamaliciousorder - file 20160324_3f8d8955bb766dba64b211b012688378.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9c1ac956f0b7efeefd3c58bf2cc6dc5332ad3434c5e5e6e0afc4505153b1e91"

  strings:
    $s1  = "var Xxl = \"cl\\x6fs\\x65\";function a(h){var _112crap = \"s\"; return \"\" + h + \"\";};var NxR = \"l\\x65\",Ask = \"ToF\\x69\"" ascii
    $s2  = "\\x65Ob\",qDD = \"\\x43rea\";var JvK = false,orn = \"CreateObject\";var KC = function CgU() {return WScript[orn](uH + dqO(GyJ) +" ascii
    $s3  = " \"lr\\x75n\",Iid = \"/\\x2f\\x66al\";var Kk = \"ht\\x74p:\";function aFm(IrM){var _112crap = \"s\"; return \"\" + IrM + \"\";};" ascii
    $s4  = "[bD](zng());var m = new this[HU](),IGz = m[sC(wY) + JW + bBh + NK]();WScript[bD](zng());var m = new this[HU](),Hl = m[wY + JW + " ascii
    $s5  = "(JvK){function zng(){return 22;};var gL = 0,eY = 0;function Oc(){var m = new this[HU](),Yp = m[wY + Pz(JW) + bBh + NK]();WScript" ascii
    $s6  = " (1, 2, 3, 4, 5, Ay); return l;};dHO = WScript[E()](rKe + W0 + Mk(Lu));jOe = dHO;jOe[(UJP)]();jOe[v0] = SKv(1);jOe[T + n0(vRK)](" ascii
    $s7  = "ion ipe() {return KC[jh + e + po + J + ZfE + bbE](s + rDW) + ZbK(ls) + BJ + S + A;}; jOe = pE(); yn = WScript[orn](jOe); var EB " ascii
    $s8  = "\"getU\\x54\",ag = \"\\x44at\\x65\";var bD = \"\\x53l\\x65\\x65p\";function Pz(Z){var _112crap = \"s\"; return \"\" + Z + \"\";}" ascii
    $s9  = "sdf76ags\" + 123313 * gL + eY; break;}}function v() {return ((Mr == true) && (Mr == YCB)) ? 1 : jyC;};if (Mr && v() && YCB){func" ascii
    $s10 = "n[hY + WmE] < 4 ) {WScript[mc](zng() * 10)};EB = jyC;} catch(iU){EB = (k + Wp, epe + lc, B + yg, 2);};}function SKv(Ay) {var l =" ascii
    $s11 = ",HUS = \"\\x6f\\x70\\x65\\x6e\";function Mk(bPu){var _112crap = \"s\"; return \"\" + bPu + \"\";};var Lu = \"r\\x65\\x61\\x6d\"," ascii
    $s12 = " hwT = \"R\\x65spo\";function n0(Oe){var _112crap = \"s\"; return \"\" + Oe + \"\";};var vRK = \"\\x65\",T = \"w\\x72it\";var v0" ascii
    $s13 = "var Xxl = \"cl\\x6fs\\x65\";function a(h){var _112crap = \"s\"; return \"\" + h + \"\";};var NxR = \"l\\x65\",Ask = \"ToF\\x69\"" ascii
    $s14 = "6e\";function lF(y){var _112crap = \"s\"; return \"\" + y + \"\";};var r1 = \"t\\x69on\",i1 = \"po\\x73i\";var L = \"od\\x79\",q" ascii
    $s15 = "ap = \"s\"; return \"\" + aS + \"\";};var kw = \"he\\x6c\\x6c\",GyJ = \"i\\x70\\x74\\x2e\\x53\";var uH = \"\\x57Scr\",D = \"jec" ascii
    $s16 = "r _112crap = \"s\"; return \"\" + N + \"\";};var NK = \"on\\x64\\x73\",bBh = \"\\x69sec\";var JW = \"\\x43Mi\\x6cl\",wY = \"g\\x" ascii
    $s17 = "x74e\";var hY = \"\\x72\\x65\\x61\\x64y\",Q = \"S\\x6c\\x65ep\";function VAL(tB){var _112crap = \"s\"; return \"\" + tB + \"\";}" ascii
    $s18 = "on p(i){var _112crap = \"s\"; return \"\" + i + \"\";};var Gw = \"\\x6fa\",uhL = \"p\\x779\\x65\";var x = \".c\\x6fm/\",sy = \"a" ascii
    $s19 = "(var w = jyC; w < zng() * 1; w++){if (Oc() != jyC){Mr = true; eY = \"07t9gasdf76ags\" + 123313 * gL + eY; YCB = true; eY = \"07t" ascii
    $s20 = "bBh + NK]();var gL = \"YG\";gL = MgJ(IGz, Yp);var eY = \"Lhk\";eY = MgJ(Hl, IGz);return MgJ(gL, eY);}var Mr = false,YCB = false;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}