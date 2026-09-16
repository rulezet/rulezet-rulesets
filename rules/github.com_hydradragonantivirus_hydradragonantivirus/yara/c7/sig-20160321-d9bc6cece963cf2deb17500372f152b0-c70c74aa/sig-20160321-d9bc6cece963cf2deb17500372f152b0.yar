rule sig_20160321_d9bc6cece963cf2deb17500372f152b0 {
  meta:
    description = "datamaliciousorder - file 20160321_d9bc6cece963cf2deb17500372f152b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a9df24d70d55234ec4c313f4bbf97ef74b676c109f1b81168c3e085385f11a3"

  strings:
    $s1  = "function w(vVw){return vVw;};function bnb(Egm){return Egm;};function KCfRy(XYsfR){return XYsfR;};var z1 = \"MP2T\";var JgNax = z" ascii
    $s2  = "r P = \"\\x62j\";var JUQ = \"e\\x4f\";var Tqp = \"\\x43reat\";var uCK = function K() {return WScript[(function HY(){return Tqp;}" ascii
    $s3  = "eh + Uu; KOvk = K0(); T = WScript[Tqp + JUQ + P + S(kFPSH)](KOvk); var czOx = true; while (czOx){try {T[(function jIjx(){return " ascii
    $s4  = "0(){return rAGHw;}()) + EE(bpUU) + A0 + vaD(cKs)] < 4 ) {WScript[QMZ + (function k0(){return c0;}())](hDBjg() * 10)};czOx = fals" ascii
    $s5  = "]();var H = x[kFR(lZda) + (function G0(){return kp;}()) + pwS(G)]();WScript[Qua(QMZ) + (function p(){return c0;}())](hDBjg());va" ascii
    $s6  = ");var rsm = x[X(lZda) + eq(kp) + G]();WScript[nGCO(QMZ) + (function qCE(){return c0;}())](hDBjg());var x = new this[PlXSr(wSCcv)" ascii
    $s7  = "};function rMv(hCLMi, YNaJN){return hCLMi - YNaJN;};function XNbqz(){return Tqp + (function q(){return JUQ;}()) + T0(P) + (funct" ascii
    $s8  = "0; ZCI < hDBjg() * 1; ZCI++){if (vcJiR() != 0){kUG = true;e = true;break;}}function vlJKx() {return kUG && e;};if (vlJKx()){tWFW" ascii
    $s9  = "e;} catch(e){};}xyPQW = WScript[XNbqz()]((function FnaDM(){return Xa;}()) + (function mwoB(){return deFVN;}()) + (function EfCBx" ascii
    $s10 = "function tz(){return DD;}())]);xyPQW[(function WXWU(){return R;}()) + (function LGr(){return AEXHr;}()) + (function JM(){return " ascii
    $s11 = "){return AL;}())](yhOSj(o) + (function HttEZ(){return nEL;}())) + YiuZw(tdKNI) + (function wxESZ(){return KGAv;}()) + sq(jRE) + " ascii
    $s12 = ";}()) + (function DXFg(){return fIVIz;}())]();b(tWFW);My = \"\" + o0(oX) + TELaD(eFl) + vkA(lDf) + (function Qq(){return Tte;}()" ascii
    $s13 = " = uCK[mJ(lF) + (function klWb(){return YOb;}()) + yKg(z) + XCy(VafC) + SK(UEw) + (function yz(){return lj;}()) + (function QtJ(" ascii
    $s14 = "JUQ) + (function aenQE(){return P;}()) + kFPSH](sCyn(vOR) + MhhU + uoehP + Uoz(Zyx));}();function b(FZRM){uCK[vtk(q0) + (functio" ascii
    $s15 = "ction JrQSH(){return t;}()) + WdOL + Ybzrf(aV) + (function aP(){return q2;}()) + (function sLqaY(){return iP;}()) + wh + mp(oIb)" ascii
    $s16 = " + BEnKC(kilD) + (function BqIeS(){return mE;}()), false);T[XzXkU(SlvK) + (function zi(){return djs;}())]();while (T[(function M" ascii
    $s17 = "T2;}())] = 0;xyPQW[(function NYCPn(){return rcdN;}()) + Uils(Nsra) + sUyp(U)](tWFW, 2 );xyPQW[WRGe + BL + (function j(){return C" ascii
    $s18 = "[(function Kyllm(){return T1;}()) + (function SbAjs(){return cGMa;}())](T[eA(hHv) + (function TqR(){return myz;}()) + Jv(jn) + (" ascii
    $s19 = "+ (function OQJz(){return b0;}()) + MzuJT + QHva + JQ(Q0) + p1 + uQO + kUG ? oPq + C0 + U0 : w(DS) + bnb(tsuo) + KCfRy(JgNax);}" fullword ascii
    $s20 = "(){return IVnNL;}()) + h(Z1));xyPQW[(IA)]();xyPQW[(function tOQMA(){return L;}()) + (function VIA(){return utYcZ;}())] = 1;xyPQW" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}