rule sig_20160321_8854eac1d46f664cab961555684bf667 {
  meta:
    description = "datamaliciousorder - file 20160321_8854eac1d46f664cab961555684bf667.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ca71dec1b30a50223da6b3319f4c37124ffdec382fc07c4eec110cc0ea0b4f2"

  strings:
    $s1  = "var c1 = \"ks2vgLNs\";var PCA = \"162\";var YUhj = \"1\\x38368\";var Suk = c1[\"cha\\x72\\x41t\"](2);function QW(KNc){return KNc" ascii
    $s2  = "AIfx;}()) + (function PR(){return gMC;}()) + TEvWs + d + BCBU]();WScript[R + kjlAF(jt) + N0](OPJD());var dEb = new this[LEyE(S)]" ascii
    $s3  = "r zhSx = \"Cre\\x61\";var Iac = function Tv() {return WScript[(function Aa(){return zhSx;}()) + boKPz(Vk) + N(sKp) + MLbH]((func" ascii
    $s4  = "eturn d;}()) + (function ByjhA(){return BCBU;}())]();WScript[(function GykOO(){return R;}()) + (function L(){return jt;}()) + (f" ascii
    $s5  = "n b;}()) + eszN(ZWFZm) + (function pVI(){return VamN;}()); i = jHz(); XKgvw = WScript[HiY(zhSx) + hjPH(Vk) + sKp + MLbH](i); var" ascii
    $s6  = "return Nctlu - FH;};function eVq(){return (function O(){return zhSx;}()) + dmH(Vk) + sKp + (function j(){return MLbH;}());};func" ascii
    $s7  = "r (var wtdmb = 0; wtdmb < OPJD() * 1; wtdmb++){if (pNBC() != 0){lYtG = true;LV = true;break;}}function f() {return lYtG && LV;};" ascii
    $s8  = "HW + c0 + Tb] < 4 ) {WScript[v0(R) + jt + Mz(N0)](OPJD() * 10)};khRC = false;} catch(e){};}UgfuO = WScript[eVq()](ify + xLWdu(vH" ascii
    $s9  = "Ifx = \"g\\x65t\";function PgFJ(jy){return jy;};function LEyE(Zk){return Zk;};var S = \"D\\x61te\";var LhGjj = \"\\x65\\x63t\";v" ascii
    $s10 = " bL(){return LfxG;}()) + (function Ljv(){return GH;}()) + eg(zJq) + O0(Zs) + (function kfJu(){return MAes;}()) + ZYRu(qnpzi) + F" ascii
    $s11 = "turn ZdTZ;}())](OZqpv, 0, 0);};function jHz(){return jluh(c) + D0 + hMB(Ovm) + nkWYN(H) + CWHrM(LhTMC);};function wJ(Nctlu, FH){" ascii
    $s12 = "tion OPJD(){return 22;};function pNBC(){var dEb = new this[PgFJ(S)]();var zM = dEb[AIfx + l(gMC) + hDv(TEvWs) + (function HL(){r" ascii
    $s13 = "n hURY(){return GWOc;}()) + JdAxQ + (function uTdX(){return HM;}()) + Vjf(KANsk));}();function a(OZqpv){Iac[(function QwDRv(){re" ascii
    $s14 = " qL;}())]();a(VJ);fcVe = \"\" + (function JyKtX(){return Mc;}()) + (function MY(){return lL;}()) + GXdTF + d1(pEwhi) + (function" ascii
    $s15 = "()) + lYtG ? (function WkFk(){return hRJH;}()) + xFb + (function BvZFo(){return J;}()) + QW(wf) : (function xf(){return Suk;}())" ascii
    $s16 = " khRC = true; while (khRC){try {XKgvw[(function Su(){return YYeE;}()) + rxXs(U)](whPIG + (function I(){return ZS;}()), (function" ascii
    $s17 = "(XKgvw[NtG + ksX + (function ddNh(){return WD;}()) + swWv + Epcpn(f0)]);UgfuO[dGACn(BICUD) + OSWrM(fRU)] = 0;UgfuO[(function nI(" ascii
    $s18 = "Q) + (function EYdx(){return BkR;}()) + X(sxHkx));UgfuO[(Ggjl(YYeE) + cXYk(U))]();UgfuO[xnLN(h0)] = 1;UgfuO[jyUwQ(hLMF) + TVqJw]" ascii
    $s19 = "if (f()){VJ = Iac[uuRTc(XZH) + (function SbLpG(){return XMEPy;}()) + VTTnV(joorD) + zFwg + (function PQDv(){return Oj;}()) + enT" ascii
    $s20 = "J(ikuA) + UTJlt + xHT](Iw + YIn) + (function ua(){return q;}()) + (function ugbaV(){return yvFNW;}()) + l0 + (function x(){retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}