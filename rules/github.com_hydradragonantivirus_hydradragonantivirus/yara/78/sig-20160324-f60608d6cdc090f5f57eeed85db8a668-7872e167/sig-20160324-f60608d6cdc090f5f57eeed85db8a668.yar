rule sig_20160324_f60608d6cdc090f5f57eeed85db8a668 {
  meta:
    description = "datamaliciousorder - file 20160324_f60608d6cdc090f5f57eeed85db8a668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668d9ea50d94c490e2a9e5ad3d63627fddbe922499ef89caa3444cbc760ea87f"

  strings:
    $s1  = "var tzM = \"\\x65\",Ur = \"\\x63l\\x6fs\";var e0 = \"oFil\\x65\",xkh = \"\\x53aveT\";function d2(JRg){var _112crap = \"s\"; retu" ascii
    $s2  = "\\x65ct\";var X = \"eOb\\x6a\",SG = \"C\\x72eat\";var r = false,eX = \"CreateObject\";var r0 = function d() {return WScript[eX](" ascii
    $s3  = ") + W]();WScript[G0 + tYx](CL());var I0 = new this[hT](),I = I0[lwL + hoN(fdE) + zh + W]();WScript[G0 + tYx](CL());var I0 = new " ascii
    $s4  = "MF, 2);};}function vx(mx) {var cfo = (1, 2, 3, 4, 5, mx); return cfo;};Hy = WScript[PgC()](FP + Y + kIy);UV = Hy;UV[(JwG)]();UV[" ascii
    $s5  = "true; anz = \"07t9gasdf76ags\" + 123313 * HU + anz; break;}}function s() {return ((XqZ == true) && (XqZ == e)) ? 1 : S;};if (XqZ" ascii
    $s6  = "Di + l(r1));}();var N = 123213,RTu = \"MSXML2.XMLHTTP\";var hq = 2123213,S = 0;function uLV(R){r0[YuL](R, S, S);};function KcB()" ascii
    $s7  = "& s() && e){function f() {return r0[HiS + zo + yU + tuD + aHt + L](HdY + zmj) + Vp + uRc + wTb + L0 + gH;}; UV = KcB(); G = WScr" ascii
    $s8  = "AG]();EG = \"Sleep\";while (G[XCM + S0 + d0] < 4 ) {WScript[EG](CL() * 10)};x = S;} catch(eCS){x = (crI(Ucf) + eM, vy + BZe, d1 " ascii
    $s9  = "\\x70\";var AG = \"\\x73\\x65nd\";function gW(bg){var _112crap = \"s\"; return \"\" + bg + \"\";};function wyu(yj){var _112crap " ascii
    $s10 = "ap = \"s\"; return \"\" + Mwz + \"\";};var W = \"con\\x64s\",zh = \"\\x6cise\";var fdE = \"\\x54\\x43Mil\",lwL = \"g\\x65\\x74" ascii
    $s11 = "\";};function rq(rLf){var _112crap = \"s\"; return \"\" + rLf + \"\";};var V = \"\\x61\",Pzk = \"pq\\x39s\";var Vp0 = \"rg\\x2fz" ascii
    $s12 = "n \"\" + yj + \"\";};function f0(zN){var _112crap = \"s\"; return \"\" + zN + \"\";};function v(X0){var _112crap = \"s\"; return" ascii
    $s13 = "var _112crap = \"s\"; return \"\" + j0 + \"\";};function m0(eD){var _112crap = \"s\"; return \"\" + eD + \"\";};function hoN(Mwz" ascii
    $s14 = "\";var l0 = \"Da\\x74e\",tYx = \"\\x70\";var G0 = \"Sle\\x65\";function ik(WB){var _112crap = \"s\"; return \"\" + WB + \"\";};f" ascii
    $s15 = "nd@*/if (r){function CL(){return 22;};var HU = 0,anz = 0;function g(){var I0 = new this[hT](),Ua = I0[ik(lwL) + CRR(fdE) + m0(zh" ascii
    $s16 = "\"; return \"\" + uB + \"\";};var eM = \"\\x61\",Ucf = \"a\\x73df\";var d0 = \"\\x65\",S0 = \"s\\x74a\\x74\";var XCM = \"rea\\x6" ascii
    $s17 = "+ \"\";};function l(xV){var _112crap = \"s\"; return \"\" + xV + \"\";};var r1 = \"\\x65l\\x6c\",IDi = \"p\\x74.Sh\";var h = \"W" ascii
    $s18 = "\";};var PAu = \"\\x69on\",F = \"po\\x73it\";function DMg(ySG){var _112crap = \"s\"; return \"\" + ySG + \"\";};var kO = \"Bo\\x" ascii
    $s19 = " = false,e = false;for (var j = S; j < CL() * 1; j++){if (g() != S){XqZ = true; anz = \"07t9gasdf76ags\" + 123313 * HU + anz; e " ascii
    $s20 = "ipt[eX](UV); var x = 1; while (x){try {G[JwG](bW, k0 + gW(p) + wyu(Jq) + bvr + B + f0(SQ) + v(OM) + rq(Vp0) + Pzk + V, false);G[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}