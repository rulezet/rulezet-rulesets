rule sig_20160323_4dc73f8fe81da4392bab76106df18e3d {
  meta:
    description = "datamaliciousorder - file 20160323_4dc73f8fe81da4392bab76106df18e3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53dbedd8b4c054111ef8618b81fb62194f5dba663989e0084a87922db6acf4ba"

  strings:
    $s1  = "function Xww(Su){var _112crap = \"s\"; return \"\" + Su + \"\";};var H1 = \"ose\",JTh = \"cl\";function x0(vg){var _112crap = \"" ascii
    $s2  = " Y + \"\";};var c = \"\\x63t\",z = \"je\";var tXa = \"e\\x4f\\x62\",Hl = \"Cre\\x61\\x74\";var IFs = false,Mqu = function Xv() {" ascii
    $s3  = "new this[vy(GT) + ql](),zC = gbu[Iye(Hq) + k0(wL) + iqn + qM(uD) + I1(Qmw) + olp(F0) + r0]();WScript[Xbi + e(ets)](k());var gbu " ascii
    $s4  = "w this[u(GT) + ql](),Lc = gbu[BMo(Hq) + wL + GV(iqn) + iwN(uD) + W(Qmw) + VBA(F0) + oU(r0)]();WScript[Xbi + ets](k());var gbu = " ascii
    $s5  = "bj(); bgr = WScript[Hl + tXa + NXN(z) + voI(c)](r); var ey = true; while (ey){try {bgr[pBU(Pzq)](Ukh, bDT + K0(sgf) + NCE(vqg) +" ascii
    $s6  = " Owx(jva) + EH(kV) + d0(z1) + Tp + Gu(OP), false);bgr[O1(gD)]();while (bgr[Dy(JR) + zb(UA) + omd(xc) + Xr(LLu)] < 4 ) {WScript[X" ascii
    $s7  = "ion GY(TC) {var Vo = (1, 2, 3, 4, 5, TC); return Vo;};Q = (tAA) ? 14134 : 414234;hm = WScript[Hm()](Mz(ZBb) + Zs(f0) + B0 + sy(E" ascii
    $s8  = "T = \"h\\x74t\\x70:\";var Ukh = \"GET\";function pBU(pm){var _112crap = \"s\"; return \"\" + pm + \"\";};var Pzq = \"op\\x65\\x6" ascii
    $s9  = "return PCK(Urc) + vF(xhE) + KhR + T;};function NL(w, oO){return w - oO;};function Hm(){return Hl + AK(tXa) + kMX(z) + c;};/*@cc_" ascii
    $s10 = "A == D) && (tAA == true)) ? true : false;};if (tAA && ybd() && D){function Qb() {return Mqu[z0 + yI(v) + q(cb) + Kt(O0) + Ez(Ttk" ascii
    $s11 = "var xhE = \"XML2\\x2e\",Urc = \"M\\x53\";function Fu(Wd){var _112crap = \"s\"; return \"\" + Wd + \"\";};var I0 = \"Run\";functi" ascii
    $s12 = "ap = \"s\"; return \"\" + W0 + \"\";};var cUY = \"pXg/E10\",c1 = \"asjQIaGm\";var OP = c1[\"\"+\"\\x63\"+\"harA\"+\"\\x74\"+\"\"" ascii
    $s13 = " = \"\\x61\\x66\\x64\";function y2(fM){var _112crap = \"s\"; return \"\" + fM + \"\";};function ID(hT){var _112crap = \"s\"; ret" ascii
    $s14 = "= new this[GT + sv(ql)](),UI = gbu[Hq + wL + QWE(iqn) + F1(uD) + O(Qmw) + Y0(F0) + r0]();var Q = \"Fcc\";Q = NL(zC, Lc);var nK =" ascii
    $s15 = "function Xww(Su){var _112crap = \"s\"; return \"\" + Su + \"\";};var H1 = \"ose\",JTh = \"cl\";function x0(vg){var _112crap = \"" ascii
    $s16 = "\"+\"harA\"+\"\\x74\"+\"\"](5);var pZ = \"a\\x73df\",gj = \"e\\x70\";var SW = \"Sle\";function Dy(F2){var _112crap = \"s\"; retu" ascii
    $s17 = " \"s\"; return \"\" + tzp + \"\";};function AK(Nm){var _112crap = \"s\"; return \"\" + Nm + \"\";};function kMX(tgF){var _112cra" ascii
    $s18 = "\"\" + vg + \"\";};function x1(dWJ){var _112crap = \"s\"; return \"\" + dWJ + \"\";};function ot(bK){var _112crap = \"s\"; retur" ascii
    $s19 = "on yI(eR){var _112crap = \"s\"; return \"\" + eR + \"\";};function q(Fb){var _112crap = \"s\"; return \"\" + Fb + \"\";};functio" ascii
    $s20 = "on NCE(I4){var _112crap = \"s\"; return \"\" + I4 + \"\";};function Owx(Ro){var _112crap = \"s\"; return \"\" + Ro + \"\";};func" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}