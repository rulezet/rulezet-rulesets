rule sig_20160321_1906d109480071086f4d79d0ec33df76 {
  meta:
    description = "datamaliciousorder - file 20160321_1906d109480071086f4d79d0ec33df76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6550f17873e8881ddcab85e794ac44bb49bd7111376426cdfbbc38c2b1c1b10d"

  strings:
    $s1  = "function UP(p0){return p0;};function YHL(QAodn){return QAodn;};var L2 = \"XPO2\";var eQA = \"\\x31\\x362\";var EUryv = \"\\x31" ascii
    $s2  = "WgvY) + d0(rz) + (function uDjOk(){return MB;}())] < 4 ) {WScript[y(R) + (function MVWox(){return lJE;}())](cm() * 10)};AJ = fal" ascii
    $s3  = "on Lh(){return xMN;}()) + (function AkILh(){return f;}()); YN = YQyT(); TNMz = WScript[(function JjkU(){return WLp;}()) + (funct" ascii
    $s4  = "n WScript[WLp + (function zQS(){return Jbz;}()) + v(oCrt) + i(ysMvR)](d + xmHr + (function vKIqH(){return FPEm;}()) + ZJAQ);}();" ascii
    $s5  = "){return Vpvg;}()) + (function SX(){return bSvE;}()) + (function qi(){return aqhEd;}())]();WScript[(function p(){return R;}()) +" ascii
    $s6  = ") + (function jCUO(){return bSvE;}()) + aqhEd]();WScript[(function Upn(){return R;}()) + Q(lJE)](cm());var hFOw = new this[jnhXo" ascii
    $s7  = "K) + yGly(YfRnM) + dtFF + (function Ka(){return lvKe;}()) + (function ZHw(){return L;}());};function yP(jyy, iiIm){return jyy - " ascii
    $s8  = ") != 0){mr = true;YNYNS = true;break;}}function OjXF() {return mr && YNYNS;};if (OjXF()){Z = C[bASz + MCY(Jhi) + (function JGANK" ascii
    $s9  = "se;} catch(e){};}JrWAF = WScript[e()](L1(rJAM) + KTwyk(f1) + (function v0(){return LlQp;}()) + (function n(){return NPS;}()));Jr" ascii
    $s10 = " we(lJE)](cm());var hFOw = new this[jnhXo + REL]();var Pcv = hFOw[(function EFHfx(){return hwjWs;}()) + ea + a0(TvodM) + ir(Vpvg" ascii
    $s11 = " (function JJJ(){return REL;}())]();var fjgRo = hFOw[(function TmczF(){return hwjWs;}()) + Ppz(ea) + CjowX(TvodM) + (function W(" ascii
    $s12 = "WAF[(lMfqO(SMuq) + kJNh)]();JrWAF[FzfWP(k) + (function Qo(){return Xotp;}())] = 1;JrWAF[(function Sn(){return ts;}()) + (functio" ascii
    $s13 = " Snd = \"F\";Snd = yP(lILep, Pcv);return yP(Y, Snd);}var mr = false;var YNYNS = false;for (var WR = 0; WR < cm() * 1; WR++){if (" ascii
    $s14 = "function j(m){C[YUd + (function PUnH(){return hdQN;}())](m, 0, 0);};function YQyT(){return (function H(){return Cf;}()) + RvYj(v" ascii
    $s15 = "YiiL(){return Wcrto;}()) + (function hWAYv(){return CsC;}()) + fSgo + (function FG(){return OSd;}()) : (function zzI(){return up" ascii
    $s16 = "n Ur(){return Gt;}())](TNMz[hmiTr + VFWa(a1) + vlJvY(KvPN)]);JrWAF[(function NGceW(){return U0;}()) + TuQYm(Qco) + P0 + DNK + fq" ascii
    $s17 = "Yu] = 0;JrWAF[cPBo + (function wqd(){return N;}()) + J(FM)](Z, 2 );JrWAF[qK(Amk) + (function y0(){return fru;}())]();j(Z);Y = \"" ascii
    $s18 = "ion xSo(){return Jbz;}()) + (function noLBe(){return oCrt;}()) + (function dGZr(){return ysMvR;}())](YN); var AJ = true; while (" ascii
    $s19 = "iiIm;};function e(){return WLp + di(Jbz) + oCrt + jv(ysMvR);};function cm(){return 22;};function a(){var hFOw = new this[jnhXo +" ascii
    $s20 = " + (function Zl(){return REL;}())]();var lILep = hFOw[(function oJpeJ(){return hwjWs;}()) + (function uU(){return ea;}()) + (fun" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}