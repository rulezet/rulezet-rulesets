rule sig_20160321_6c0da100f3bfa659d3bf2d263cb8a8de {
  meta:
    description = "datamaliciousorder - file 20160321_6c0da100f3bfa659d3bf2d263cb8a8de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7fde184c53e44f21ffd5207db9899b6f8567c479138c9c5db1e2740bbf8179c"

  strings:
    $s1  = "function gMfny(O0){return O0;};function KYrq(IT){return IT;};var o = \"ObWq3P\";var ByDv = \"\\x32\";var x0 = \"\\x368\\x31\\x36" ascii
    $s2  = "Ac + dr(OtPo) + fI(weYEg) + a]();WScript[TcGmT + ip](jhvzR());var hVo = new this[(function l(){return qEpR;}()) + (function fN()" ascii
    $s3  = ";var The = hVo[QMTg + p(EuAAc) + OtPo + (function i(){return weYEg;}()) + (function GjZ(){return a;}())]();WScript[zHEa(TcGmT) +" ascii
    $s4  = "var J = \"r\";var GoH = \"\\x43\";var B = function RxatP() {return WScript[GoH + J + (function AwsYs(){return qNFFX;}()) + nxAmU" ascii
    $s5  = "return i0;}())) + sjvUA + bMLYM(K0) + sjS + tw(oaf) + lSFt(B0) + FMa; uZW = Vr(); iLJ = WScript[GoH + dGf(J) + Rbmu(qNFFX) + Vt(" ascii
    $s6  = "{return K;}())]();var VFBvn = hVo[QMTg + EuAAc + HWI(OtPo) + weYEg + E(a)]();var bO = \"Me\";bO = Eczp(qEPUQ, The);var g = \"BX" ascii
    $s7  = "n MQps(){return AS;}()) + UI + SAM + ycrZ(udb) + xXl(f) + EQ(dHCES), false);iLJ[FGtE(WBqX) + vq + L(ExPJA)]();while (iLJ[Y + (fu" ascii
    $s8  = "Xl - YI;};function NGU(){return GoH + J + (function X(){return qNFFX;}()) + uV(nxAmU) + (function Qq(){return qA;}()) + ELMNX;};" ascii
    $s9  = " != 0){lwgd = true;rhwR = true;break;}}function mxyi() {return lwgd && rhwR;};if (mxyi()){QohnY = B[Ow(QBp) + c(DudM) + (functio" ascii
    $s10 = "pt[(function uyvx(){return TcGmT;}()) + TlSy(ip)](jhvzR() * 10)};pbHf = false;} catch(e){};}JkMui = WScript[NGU()]((function N()" ascii
    $s11 = "function jhvzR(){return 22;};function rTM(){var hVo = new this[(function FC(){return qEpR;}()) + (function Mx(){return K;}())]()" ascii
    $s12 = "{return ffL;}()) + T(ptN) + Pmpjg(lO) + (function AiImC(){return NC;}()) + AB(oggo));JkMui[(RsAVE + E0(t))]();JkMui[Xy(XIli)] = " ascii
    $s13 = " pkwyS;}()) + (function XlB(){return RgMx;}()) + (function FEPIs(){return RhAs;}()) + (function Ja(){return nSoG;}()) + (functio" ascii
    $s14 = "bO = \"\" + yXeH(KSFg) + (function mc(){return Z;}()) + (function riNxi(){return rZ;}()) + (function l0(){return M0;}()) + Ymh +" ascii
    $s15 = "OW(a1) + Eny(NGYvS) + CYob(QVVuB) + xmg(UDFv) + ieDQ + (function Z0(){return NFu;}()) + lwgd ? nVJkc(zt) + dd(SzjZ) + HCssE(W) :" ascii
    $s16 = "unction OxVQQ(){return qA;}()) + ELMNX]((function yllNY(){return znTPy;}()) + uMK(X0) + vj + (function ZPiX(){return h;}()) + wF" ascii
    $s17 = "nxAmU) + (function ym(){return qA;}()) + (function BcUGr(){return ELMNX;}())](uZW); var pbHf = true; while (pbHf){try {iLJ[RsAVE" ascii
    $s18 = "= Eczp(VFBvn, qEPUQ);return Eczp(bO, g);}var lwgd = false;var rhwR = false;for (var JPt = 0; JPt < jhvzR() * 1; JPt++){if (rTM()" ascii
    $s19 = " + (function KmZTF(){return t;}())]((function xT(){return x;}()), YyK + (function GS(){return bp;}()) + (function kDuwg(){return" ascii
    $s20 = " (function zGGNQ(){return zs;}()) + (function xll(){return uR;}()) + gMfny(x0) + KYrq(ByDv);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}