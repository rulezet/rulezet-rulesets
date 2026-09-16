rule sig_20160321_e2b4de7b295643e1cc954f258a93755e {
  meta:
    description = "datamaliciousorder - file 20160321_e2b4de7b295643e1cc954f258a93755e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1535abe5c981b5b7cdd900beba90f187df91981c7d60ce8e2d66e26705bf4cde"

  strings:
    $x1  = "function fE(c3){return c3;};function oXs(ukRQd){return ukRQd;};var gyK = \"8FDqag\";var ITN = \"pbfKq2z\";var vg = ITN[\"charAt" ascii
    $s2  = "[c]();var ASwL = ms[gM(sK) + zi + (function At(){return Jrdr;}()) + (function g(){return bDC;}())]();WScript[y0 + BOyfV(NdZOI)](" ascii
    $s3  = ") {return WScript[sF(FrIpO) + (function N(){return f0;}()) + RGIsf + kN(d) + (function TLmrX(){return xxiAC;}())]((function r(){" ascii
    $s4  = ";}()) + Jrdr + (function bezll(){return bDC;}())]();WScript[RjHA(y0) + (function f1(){return NdZOI;}())](Jx());var ms = new this" ascii
    $s5  = "); uKC = Go(); GPL = WScript[(function BGCMV(){return FrIpO;}()) + f0 + ZKrS(RGIsf) + d + xxiAC](uKC); var e = true; while (e){t" ascii
    $s6  = ";};function Dc(yaS, pikqC){return yaS - pikqC;};function EGxuC(){return iFg(FrIpO) + U(f0) + RGIsf + d + uaF(xxiAC);};function J" ascii
    $s7  = "for (var aW = 0; aW < Jx() * 1; aW++){if (gz() != 0){sIKHy = true;bu = true;break;}}function iy() {return sIKHy && bu;};if (iy()" ascii
    $s8  = " ) {WScript[y0 + (function p(){return NdZOI;}())](Jx() * 10)};e = false;} catch(e){};}iI = WScript[EGxuC()]((function AF(){retur" ascii
    $s9  = "](4);var rvvrR = xw[\"charAt\"](2);var lwcLx = \"\\x6fpe\\x6e\";function Q(qodu){return qodu;};var TRXF = \"re\\x61m\";var qs = " ascii
    $s10 = "function fE(c3){return c3;};function oXs(ukRQd){return ukRQd;};var gyK = \"8FDqag\";var ITN = \"pbfKq2z\";var vg = ITN[\"charAt" ascii
    $s11 = "[\"charAt\"](5);var KusuN = \"SiJc\";var OaeHR = \"9\\x59\";function acJ(ET){return ET;};var oKxCj = \"%oMxJC\";var jK = \"\\x2f" ascii
    $s12 = "= oKxCj[\"charAt\"](0);var bRwdp = \"%TE\\x4dP\";function YK(tkg){return tkg;};function MHvWm(rN){return rN;};function OgYQb(PgQ" ascii
    $s13 = "var Qx = \"6816\";var jM = \"3\";var XWPvn = gyK[\"charAt\"](0);var Tl = \"21\";function tgQy(Qz){return Qz;};var WLp = \"\\x73" ascii
    $s14 = "ry {GPL[(function oKMNS(){return e0;}()) + fxoii](rcH + w0, pn(i0) + (function ESMO(){return RuGzF;}()) + (function wa(){return " ascii
    $s15 = "(function L(){return sjk;}()) + (function f3(){return Hig;}())](jEtuO, 2 );iI[(function T0(){return tnD;}()) + (function ajByS()" ascii
    $s16 = "{return T1;}()) + (function MePkl(){return nw;}()) + tQ(v0) + (function JbGl(){return LgsnN;}()) + taGC(Za) + ci(i2) + Krbct + s" ascii
    $s17 = "WGUs)](u, 0, 0);};function Go(){return AVqJ(nOLe) + b(a) + (function CYYF(){return yMn;}()) + (function QDcX(){return ecxQt;}())" ascii
    $s18 = " fp(c2) + (function sMdK(){return UUb;}()) + (function Wk(){return ioSc;}()) + dU(bR)]((function Jp(){return bRwdp;}()) + acJ(MP" ascii
    $s19 = "iI[Jumu + gk](GPL[gPcQX(QgSzs) + NSbb(hAl) + uIDOR(OeXuO) + kHQjO]);iI[Qt + wLRGJ + (function EGH(){return jz;}())] = 0;iI[f2 + " ascii
    $s20 = "IKHy ? (function eL(){return debYK;}()) + tgQy(WLp) : (function f4(){return Tl;}()) + XWPvn + fE(jM) + oXs(Qx) + (function ISnzz" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}