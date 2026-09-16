rule sig_20160324_bae6c14d605854c85791089217e4a638 {
  meta:
    description = "datamaliciousorder - file 20160324_bae6c14d605854c85791089217e4a638.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90fe73cfc16eb4cbfc159b66623239c264910f65356e0f81489a2a5e9227e14f"

  strings:
    $s1  = "function FCg(uo){var _112crap = \"s\"; return \"\" + uo + \"\";};function S1(af){var _112crap = \"s\"; return \"\" + af + \"\";}" ascii
    $s2  = "\\x74t\\x70\",paS = TNN[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](1);function FF(O2){var _112crap = \"s\"; return \"" ascii
    $s3  = " + L(G0)]();WScript[i1(nW) + O0](D());var QV = new this[JEj + liT](),r = QV[Jj(EdW) + Yfz(YT) + IRO(pj) + iUk(frm) + d0(p0) + G0" ascii
    $s4  = " + oR(p0) + G0]();WScript[VdK(nW) + mT(O0)](D());var QV = new this[Nl(JEj) + TM(liT)](),R = QV[EdW + JWQ(YT) + pj + frm + Vq(p0)" ascii
    $s5  = "OJ = function GJ() {return WScript[tEz(dj) + AF(vgQ) + OT(D0) + H(rS) + wxW(ujC)](Wbf + M0(j) + hpJ + V + w(E1) + y(j0));}();fun" ascii
    $s6  = "vI);}; gp = Bo(); EK = WScript[M(dj) + c(vgQ) + D0 + Z0(rS) + N(ujC)](gp); var E0 = true; while (E0){try {EK[Q0(n0) + yex(Riw)](" ascii
    $s7  = " KP = \"f\\x64\",s0 = bf[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](2);function J(Mx){var _112crap = \"s\"; return \"" ascii
    $s8  = "2crap = \"s\"; return \"\" + DqC + \"\";};var iCK = \"6cdzuOt\",ZZT = \"bLi7sC4b\";var G0 = ZZT[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"" ascii
    $s9  = " return \"\" + F1 + \"\";};var H1 = \"68wVpAC\",h1 = \"tion\";var A2 = \"\\x6f\\x73i\",G3 = H1[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"" ascii
    $s10 = "\";var p = xA[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](3);function wRX(b){var _112crap = \"s\"; return \"\" + b + " ascii
    $s11 = "(hl){var _112crap = \"s\"; return \"\" + hl + \"\";};var EJv = \"e\",mk = EJv[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt" ascii
    $s12 = "; return \"\" + XGd + \"\";};var bf = \"e8ar9b\",zYJ = \"SObJRap\";var q0 = zYJ[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"r" ascii
    $s13 = "ction yo(NI){fOJ[s(uc)](NI, 0, 0);};function Bo(){return V0 + wRX(WeP) + hGh(T) + i0(YE);};function d(uk, Pcd){return uk - Pcd;}" ascii
    $s14 = "pQf + X; break;}}function i() {return ((sL == vo) && (sL == true)) ? true : false;};if (sL && i() && vo){function QP() {return f" ascii
    $s15 = "+ \"\";};function ur(biN){var _112crap = \"s\"; return \"\" + biN + \"\";};var z = \"\\x72ing\\x73\",H0 = \"ent\\x53t\";var rhi " ascii
    $s16 = "jX(h0)]();while (EK[hj(P) + snt + vIL(pcW)] < 4 ) {WScript[OQ(nW) + q(O0)](D() * 10)};E0 = false;} catch(o){E0 = (wyg + qLU, J(B" ascii
    $s17 = " bF = \"YydCLtgQ3\",U = \"e\";var h = bF[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](5),K = \"\\x44\\x61\";function Vd" ascii
    $s18 = "var pa = \"rNeqM8p2\",mZY = pa[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](2);var f = \"o\\x46il\",xnE = \"S\\x61veT\"" ascii
    $s19 = "ar dg = \"EGpAR\",w0 = \"M\\x50\\x25/\";var i2 = dg[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](0),xz = \"%\\x54\";fun" ascii
    $s20 = " = iCK[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](2);var frm = \"\\x73econ\",pj = \"li\";var YT = \"\\x43Mil\",EdW = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}