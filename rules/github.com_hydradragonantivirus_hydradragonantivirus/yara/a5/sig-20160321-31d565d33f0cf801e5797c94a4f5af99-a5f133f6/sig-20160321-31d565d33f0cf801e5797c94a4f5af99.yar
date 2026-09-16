rule sig_20160321_31d565d33f0cf801e5797c94a4f5af99 {
  meta:
    description = "datamaliciousorder - file 20160321_31d565d33f0cf801e5797c94a4f5af99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd6f1375c2fbd047f3e498d2983c49bbe18cd5816b24a94ab51e21e4edff63cc"

  strings:
    $s1  = "function Xr(hn){return hn;};var CIbee = \"62\";var qs = \"\\x31\";var aCk = \"68\";var l1 = \"218\\x33\";var G = \"fasd\\x66\";v" ascii
    $s2  = "x = \"eOb\";var mt = \"\\x43re\\x61t\";var s = function TZyrl() {return WScript[(function mtm(){return mt;}()) + SXu(Lsex) + jmb" ascii
    $s3  = "nction aJrd(){return eY;}()) + (function l(){return EZUmk;}()) + tqJB(Rc) + (function ZC(){return c;}())]();WScript[MNI + (funct" ascii
    $s4  = "Ne = rhBrL[Kx(cwq) + (function pvQJ(){return eY;}()) + EZUmk + Rc + (function wRey(){return c;}())]();WScript[XhnC(MNI) + (funct" ascii
    $s5  = "FyF) + UJ(GUYO); V = Qe(); KY = WScript[mt + jMa(Lsex) + (function Bc(){return iFkX;}()) + ukL(AWmZx)](V); var FlqC = true; whil" ascii
    $s6  = "bAd) + (function pqhXb(){return BJib;}())] < 4 ) {WScript[MNI + (function QhtVi(){return eUF;}()) + tk](RBFnX() * 10)};FlqC = fa" ascii
    $s7  = "ion q(){return eUF;}()) + (function wQ(){return tk;}())](RBFnX());var rhBrL = new this[pBwrj(z)]();var wKfTP = rhBrL[(function s" ascii
    $s8  = "rn ZyZV - X;};function h(){return mt + t0(Lsex) + (function FYVWk(){return iFkX;}()) + OIJn(AWmZx);};function RBFnX(){return 22;" ascii
    $s9  = "BFnX() * 1; RX++){if (fXVBV() != 0){TCE = true;QZJ = true;break;}}function iBZT() {return TCE && QZJ;};if (iBZT()){vbBL = s[i + " ascii
    $s10 = ") + (function L0(){return Coj;}()) + (function wk(){return E;}()) + MP(ZyUT) + oCX, false);KY[x0(ie)]();while (KY[wg(z1) + eAmA(" ascii
    $s11 = "lse;} catch(e){};}cHB = WScript[h()]((function CQgrh(){return xBK;}()) + Wptaq(net) + VKKir(aac) + (function LjA(){return ctcb;}" ascii
    $s12 = "= kGL(HNe, RjEIz);var jO = \"YqA\";jO = kGL(wKfTP, HNe);return kGL(L, jO);}var TCE = false;var QZJ = false;for (var RX = 0; RX <" ascii
    $s13 = "ion lFWP(){return eUF;}()) + (function B(){return tk;}())](RBFnX());var rhBrL = new this[(function hLoO(){return z;}())]();var H" ascii
    $s14 = "e (FlqC){try {KY[u](wDd(cvrsd) + (function FiC(){return dgq;}()), AVRE + RHOtc(EG) + U + CH(ka) + (function a1(){return BPui;}()" ascii
    $s15 = " (function CQ(){return dteNL;}()) + (function N(){return DpLgY;}()) + i0(UhQ) + qB(nwhj) + VO + iBtgU(hd) + koIyd + Lm + TCE ? (" ascii
    $s16 = "tP + (function ggs(){return pgo;}()) + xLpkP + W + gNp(l0) + orxIf + tbxNN(LMT) + URQwE + (function ZB(){return si;}())]((functi" ascii
    $s17 = "function azmot(){return IUKE;}()) + G : (function Habko(){return l1;}()) + Xr(aCk) + qs + (function bIO(){return CIbee;}());}" fullword ascii
    $s18 = "};function fXVBV(){var rhBrL = new this[(function ToM(){return z;}())]();var RjEIz = rhBrL[(function NxY(){return cwq;}()) + (fu" ascii
    $s19 = "on OrQ(){return z0;}()) + pv(kxlp) + fki) + (function x(){return gMa;}()) + (function XOl(){return ryhsN;}()) + laq(a0) + YGy(sb" ascii
    $s20 = "()));cHB[(u)]();cHB[(function ymdek(){return GH;}()) + zU + f] = 1;cHB[(function OjgbF(){return NKwy;}()) + (function km(){retur" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}