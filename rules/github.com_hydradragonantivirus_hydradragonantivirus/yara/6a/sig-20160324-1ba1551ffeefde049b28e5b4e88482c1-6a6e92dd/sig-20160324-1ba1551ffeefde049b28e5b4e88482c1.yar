rule sig_20160324_1ba1551ffeefde049b28e5b4e88482c1 {
  meta:
    description = "datamaliciousorder - file 20160324_1ba1551ffeefde049b28e5b4e88482c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38b8b4e3e66fdcdc07aa66d7e354e69b6b9a3d4d8681d0bbcf30042cfb025802"

  strings:
    $s1  = "; return Jt;};pFR = WScript[wd()](qY + syw + kx);Ljo = pFR;Ljo[(mFU(tae))]();Ljo[Z1] = XEU(1);Ljo[aBo](S[nWj + roW + v0(wza)]);L" ascii
    $s2  = "XML2.XMLHTTP\";var Ft = 2123213,OA = 0;function sv(rU){s[xO](rU, OA, OA);};function g(){return c;};function BMt(b, lB){return b " ascii
    $s3  = "ew this[Jk(Uq)](),UE = Y[s0 + qCt(D) + vH + Uk]();WScript[VPg(fE) + fNt(eDR)](a());var Y = new this[Uq](),Oy = Y[s0 + D + vH + y" ascii
    $s4  = "rn s[Bn + RWT(zzd) + L + gK + o](Mkt + Jht) + YRC(dkE) + Uv(k0) + bM + ydl;}; Ljo = g(); S = WScript[e](Ljo); var h = 1; while (" ascii
    $s5  = "QD = 0,z = 0;function eeq(){var Y = new this[Uq](),tsT = Y[s0 + kg(D) + vH + W(Uk)]();WScript[loP(fE) + moZ(eDR)](a());var Y = n" ascii
    $s6  = "var c1 = \"cl\\x6fse\",RTN = \"oF\\x69\\x6ce\";var zWS = \"\\x53\\x61veT\";function g0(O0){var _112crap = \"s\"; return \"\" + O" ascii
    $s7  = " 123313 * kQD + z; break;}}function PX() {return ((Dh == true) && (Dh == i)) ? 1 : OA;};if (Dh && PX() && i){function nW() {retu" ascii
    $s8  = "var caT = false,e = \"CreateObject\";var s = function RIY() {return WScript[e](xhd(RL) + CDI + kI(q));}();var Chh = 123213,c = " ascii
    $s9  = "4 ) {WScript[xNU](a() * 10)};h = OA;} catch(er){h = (QJ, HI(l) + kLA, r + gb, 2);};}function XEU(V) {var Jt = (1, 2, 3, 4, 5, V)" ascii
    $s10 = "crap = \"s\"; return \"\" + WAf + \"\";};function VPg(VD){var _112crap = \"s\"; return \"\" + VD + \"\";};function fNt(apa){var " ascii
    $s11 = "ction Jk(VAN){var _112crap = \"s\"; return \"\" + VAN + \"\";};var Uq = \"Dat\\x65\",xO = \"Ru\\x6e\";var Nvn = \"\\x50\",ZKd = " ascii
    $s12 = "var c1 = \"cl\\x6fse\",RTN = \"oF\\x69\\x6ce\";var zWS = \"\\x53\\x61veT\";function g0(O0){var _112crap = \"s\"; return \"\" + O" ascii
    $s13 = "ADOD\\x42\",gb = \"\\x66a\";var r = \"afd\\x61\";function HI(M0){var _112crap = \"s\"; return \"\" + M0 + \"\";};var kLA = \"\\x" ascii
    $s14 = "; return \"\" + z0 + \"\";};var q = \"\\x65ll\",CDI = \"\\x70t.Sh\";var RL = \"WS\\x63ri\",puO = \"e\\x63t\";var NB = \"e\\x4fbj" ascii
    $s15 = "rap = \"s\"; return \"\" + v + \"\";};var tae = \"ope\\x6e\";function YRC(olz){var _112crap = \"s\"; return \"\" + olz + \"\";};" ascii
    $s16 = "x66\";var QJ = \"\\x61sdf\\x61\";function Hc(s1){var _112crap = \"s\"; return \"\" + s1 + \"\";};var p = \"\\x65\",z1 = \"st\\x6" ascii
    $s17 = "12crap = \"s\"; return \"\" + E + \"\";};var Uk = \"\\x6e\\x64s\",vH = \"i\\x73\\x65c\\x6f\";var D = \"C\\x4dil\\x6c\",s0 = \"" ascii
    $s18 = " \"r\\x65ad\\x79\",k1 = \"\\x70\";var KVU = \"S\\x6cee\",Zmf = \"s\\x65nd\";function o0(hEj){var _112crap = \"s\"; return \"\" +" ascii
    $s19 = "r O = \"L2\\x2eX\\x4d\",Pk = \"MSX\\x4d\";function xhd(rD){var _112crap = \"s\"; return \"\" + rD + \"\";};function kI(z0){var _" ascii
    $s20 = "s\"; return \"\" + apa + \"\";};var eDR = \"\\x70\",fE = \"Sl\\x65\\x65\";function kg(c0){var _112crap = \"s\"; return \"\" + c0" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}