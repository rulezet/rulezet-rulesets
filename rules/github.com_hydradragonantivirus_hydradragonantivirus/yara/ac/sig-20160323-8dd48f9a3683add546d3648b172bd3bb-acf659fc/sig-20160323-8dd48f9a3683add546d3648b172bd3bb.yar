rule sig_20160323_8dd48f9a3683add546d3648b172bd3bb {
  meta:
    description = "datamaliciousorder - file 20160323_8dd48f9a3683add546d3648b172bd3bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "792d108db9ded901b24e1d21eeccab1a99e29e8e4c5e323bf669bdc59a6214e3"

  strings:
    $s1  = "function N0(B2){var _112crap = \"s\"; return \"\" + B2 + \"\";};function ZT(x1){var _112crap = \"s\"; return \"\" + x1 + \"\";};" ascii
    $s2  = "+ GuS, true);};}function hY(mgW) {var nxJ = (1, 2, 3, 4, 5, mgW); return nxJ;};x0 = (Z) ? 14134 : 414234;YnG = WScript[Zgs()](Pd" ascii
    $s3  = "a\\x74eOb\";var n0 = \"\\x43re\",rKw = false;var eP = function DYN() {return WScript[n1(n0) + coe + I(r0)](o(E) + X(QDJ) + b1 + " ascii
    $s4  = " lCL(k) + iY + Zq(jwB)]();WScript[PF(LXS) + wPp(Gd)](b());var x = new this[oa(z0) + V0 + dY](),kWT = x[cy + o0(qch) + uP(W0) + G" ascii
    $s5  = "eS(z1) + k + clt(iY) + jwB]();WScript[cM(LXS) + K(Gd)](b());var x = new this[u(z0) + V0 + jT(dY)](),W = x[Fxq(cy) + AMW(qch) + D" ascii
    $s6  = " OH(qmY){var _112crap = \"s\"; return \"\" + qmY + \"\";};var Lf = \"fa\",phm = \"a\\x73d\";var YW = \"p\",u0 = YW[\"ch\"+\"\\x6" ascii
    $s7  = "turn \"\" + gxt + \"\";};function jW(OWj){var _112crap = \"s\"; return \"\" + OWj + \"\";};var aE = \"cmEClc\",pfB = aE[\"ch\"+" ascii
    $s8  = "nction U0(L){var _112crap = \"s\"; return \"\" + L + \"\";};var EfD = \"uu58R/\",fwH = EfD[\"ch\"+\"\\x61\"+\"rAt\"](5);var PWh " ascii
    $s9  = "){var _112crap = \"s\"; return \"\" + cP + \"\";};var pYW = \"tWvs0Mn5\",w = \"6gDG4\";var VJ = \"\\x73\",k0 = w[\"ch\"+\"\\x61" ascii
    $s10 = "1\"+\"rAt\"](5);var m2 = \"\\x54\",tM = \"Sav\\x65\";function a2(fkO){var _112crap = \"s\"; return \"\" + fkO + \"\";};function " ascii
    $s11 = "r v0 = \"dDsBv8Nc\",KDp = \"en\\x64\";var mnO = v0[\"ch\"+\"\\x61\"+\"rAt\"](2);function cb(l){var _112crap = \"s\"; return \"\"" ascii
    $s12 = "1 = \"\\x52\";function AEx(yrl){var _112crap = \"s\"; return \"\" + yrl + \"\";};var qL = \"ee\",s1 = qL[\"ch\"+\"\\x61\"+\"rAt" ascii
    $s13 = "p = \"s\"; return \"\" + SNu + \"\";};var XeG = \"GET\";function xq(nRx){var _112crap = \"s\"; return \"\" + nRx + \"\";};functi" ascii
    $s14 = " R1 = MoU[\"ch\"+\"\\x61\"+\"rAt\"](0),ryW = \"adf\\x61\";var p2 = \"f\";function Neo(lT){var _112crap = \"s\"; return \"\" + lT" ascii
    $s15 = " \"get\\x55\";function IMM(RR){var _112crap = \"s\"; return \"\" + RR + \"\";};function TSf(fB){var _112crap = \"s\"; return \"" ascii
    $s16 = " = \"eHDhs2\";var oT = \"at\\x65\",aw = FF[\"ch\"+\"\\x61\"+\"rAt\"](2);function PF(FQ){var _112crap = \"s\"; return \"\" + FQ +" ascii
    $s17 = "Hzm() && Vyf){function r() {return eP[qJz(M1) + X4(qvj) + Bg(i) + n2(MT) + vNM(NF) + pO(vn) + LYs(kRD) + r2(A) + k0 + SO(VJ)](NE" ascii
    $s18 = "turn \"\" + B0 + \"\";};var lU = \"HT\\x54P\",r1 = \".XML\";var AH = \"\\x58ML\\x32\",q = \"\\x4dS\";function PTL(M){var _112cra" ascii
    $s19 = "nv = \"07t9gasdf76ags\" + 123313 * x0 + Fnv; break;}}function Hzm() {return ((Z == Vyf) && (Z == true)) ? true : false;};if (Z &" ascii
    $s20 = "< 4 ) {WScript[LXS + Gd](b() * 10)};NZN = false;} catch(ThW){NZN = (Neo(phm) + OH(Lf), uRu(p2) + XY(ryW) + loe(R1) + m1(T0), Hv " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}