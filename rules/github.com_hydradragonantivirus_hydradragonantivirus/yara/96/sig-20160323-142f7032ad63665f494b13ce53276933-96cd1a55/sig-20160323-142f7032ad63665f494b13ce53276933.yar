rule sig_20160323_142f7032ad63665f494b13ce53276933 {
  meta:
    description = "datamaliciousorder - file 20160323_142f7032ad63665f494b13ce53276933.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93cb4420ed55d2b7d059bec671c10fe3f740fa41833cf19db14501a9848b1b5e"

  strings:
    $s1  = "function O0(nCJ){var _112crap = \"s\"; return \"\" + nCJ + \"\";};function EK(jFE){var _112crap = \"s\"; return \"\" + jFE + \"" ascii
    $s2  = ") + C0(fL)](),yr = Box[s + xPr + WN(bQW) + cQl(aYR) + a0(c) + v]();WScript[KAo(j2) + M](j());var Box = new this[N(x) + jAl(Ku) +" ascii
    $s3  = "VV(M4) + Sz(Y2) + ZWY(b0) + ye(dbW), false);j1[JW + R4(ykH) + PHp(Gjz)]();while (j1[veP + n(GN) + eUm(AX)] < 4 ) {WScript[TT0(j2" ascii
    $s4  = "fL)](),P = Box[kqo(s) + CT(xPr) + ReK(bQW) + N0(aYR) + XD(c) + cK(v)]();WScript[j2 + j3(M)](j());var Box = new this[i0(x) + z(Ku" ascii
    $s5  = "x74\\x65O\",wf = \"\\x43r\\x65\\x61\";var LdO = false,ie = function WPt() {return WScript[qrd(wf) + jw + iPQ(w0) + vuj(lg)](TfC(" ascii
    $s6  = "2crap = \"s\"; return \"\" + ohU + \"\";};var sir = \"asdfa\",RPF = \"GpD\";var YcE = RPF[\"ch\"+\"\\x61\"+\"rAt\"](1),T0 = \"Sl" ascii
    $s7  = "n \"\" + EZ + \"\";};var VkG = \"zYx2GBHRf\",UK = \"T\";var Dhv = \"E\",vj0 = VkG[\"ch\"+\"\\x61\"+\"rAt\"](4);function R3(ik){v" ascii
    $s8  = "\"+\"\\x61\"+\"rAt\"](0);function YZ(NdK){var _112crap = \"s\"; return \"\" + NdK + \"\";};function Q(ZDw){var _112crap = \"s\";" ascii
    $s9  = "\"\";};function KPL(r0){var _112crap = \"s\"; return \"\" + r0 + \"\";};var L = \"SBW\",bu = \"\\x6fdy\";var Bfs = L[\"ch\"+\"" ascii
    $s10 = "\"\";};function e0(S0){var _112crap = \"s\"; return \"\" + S0 + \"\";};var v0 = \"d7hGqStlTY\",M = \"leep\";var j2 = v0[\"ch\"+" ascii
    $s11 = "ch\"+\"\\x61\"+\"rAt\"](4);var J = \"R\\x75\";function TfC(t){var _112crap = \"s\"; return \"\" + t + \"\";};function S(Zjz){var" ascii
    $s12 = " + \"\";};var rVg = \"Kn\",Bfu = \"ERdJPo\";var Gjz = Bfu[\"ch\"+\"\\x61\"+\"rAt\"](2),ykH = rVg[\"ch\"+\"\\x61\"+\"rAt\"](1);va" ascii
    $s13 = " EGm + \"\";};var sp = \"gYCeMq\",aI = sp[\"ch\"+\"\\x61\"+\"rAt\"](3);var qm = \"il\",Pl = \"e\\x54oF\";var jxd = \"Sav\";funct" ascii
    $s14 = "+\"\\x61\"+\"rAt\"](0);var vLR = \"daf\",Ors = \"af\";function Ef(JU){var _112crap = \"s\"; return \"\" + JU + \"\";};function z" ascii
    $s15 = "q;};function ZfJ(g, XcE){return g - XcE;};function h(){return Il(wf) + Nn(jw) + w0 + Xqh(lg);};/*@cc_on  @if (@_win32 || @_win64" ascii
    $s16 = "& (NZs == true)) ? true : false;};if (NZs && luZ() && G){function D() {return ie[UY(J3) + Oqw(k) + BT(lUp) + x0 + ur + Z(CGl) + " ascii
    $s17 = "\";var veP = \"read\";function R4(BR){var _112crap = \"s\"; return \"\" + BR + \"\";};function PHp(nl){var _112crap = \"s\"; ret" ascii
    $s18 = " ZEW(a3), true);};}function I(j0) {var PRF = (1, 2, 3, 4, 5, j0); return PRF;};Ctf = (NZs) ? 14134 : 414234;ry = WScript[h()](Y3" ascii
    $s19 = "JB[\"ch\"+\"\\x61\"+\"rAt\"](1),JY = \"//\";var P0 = z0[\"ch\"+\"\\x61\"+\"rAt\"](3),Ee = \"tt\\x70\";var Wr = \"\\x68\";functio" ascii
    $s20 = "q0[\"ch\"+\"\\x61\"+\"rAt\"](3),tp = \"d\";var U = \"s\",F0 = mJ[\"ch\"+\"\\x61\"+\"rAt\"](4);var jZl = \"d\\x66\",SW = \"fa\";f" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}