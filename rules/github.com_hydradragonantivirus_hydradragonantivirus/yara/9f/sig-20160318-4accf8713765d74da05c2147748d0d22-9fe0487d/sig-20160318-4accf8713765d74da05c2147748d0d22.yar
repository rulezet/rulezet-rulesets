rule sig_20160318_4accf8713765d74da05c2147748d0d22 {
  meta:
    description = "datamaliciousorder - file 20160318_4accf8713765d74da05c2147748d0d22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2de014db94ba719ccade53bde38086a77f91b22e400e70cd4ea804562a896daa"

  strings:
    $x1  = "var Eb = \"\\x21\";var CE = \"in\";var InlU = \"\\x79 ag\\x61\";var Zei = \" tr\";var nh = \"\\x61s\\x65,\";var SszG = \"Ple\";v" ascii
    $s2  = " RX(){return QVpv;}()) + (qZ) + (function zE(){return OxjF;}()) + (G);}else{WScript.Echo((SszG) + (function jE(){return nh;}()) " ascii
    $s3  = ") + (function BgRE(){return hZKq;}()); scq = mX(); k = WScript[(function Qx(){return lRHzx;}()) + (function E(){return gPpj;}())" ascii
    $s4  = " {return WScript[(lRHzx) + (gPpj) + (function It(){return DOzGH;}()) + (function Yye(){return zQNAq;}())]((function smZ(){return" ascii
    $s5  = " vq(){return zeMqg;}()) + (kpgKr) + (function nQ(){return Pb;}())]();WScript[(function kcG(){return q;}()) + (function tpL(){ret" ascii
    $s6  = "< 4 ) {WScript[(function yk(){return q;}()) + (lBqFX)](wflna() * 10)};QH = WScript[smH()]((function xyok(){return Kb;}()) + (fun" ascii
    $s7  = "1) + (function fTBa(){return la;}());};function da(Uu, zYpr){return Uu - zYpr;};function smH(){return (function gyp(){return lRH" ascii
    $s8  = " \"t\\x4d\\x69\";var ACSou = \"e\";var psSx = \"9uYDjgwlZB\"[\"charAt\"](5);var jgzW = \"ate\";var bQo = \"kcVeDE\"[\"charAt\"](" ascii
    $s9  = " + (function OXDZH(){return ZK;}()) + (cS) + (function vWE(){return VoTA;}()) + (UjA) + (Sv), false);k[(function mZj(){return sc" ascii
    $s10 = "R\";tgqdr = da(rSh, XOiXg);return da(nnte, tgqdr);}var WM = false;var gLi = false;for (var Rl = 0; Rl < wflna() * 1; Rl++){if (N" ascii
    $s11 = " OzZ(){return Ja;}()) + (YcD) + (function kKsuS(){return Nk;}()) + (function xVFj(){return t0;}()) + (Ky) + (function NOXl(){ret" ascii
    $s12 = "n(){return w0;}()) + (wsV) + WM ? (Hv) + (function TmJXH(){return PsOkp;}()) + (function ynQ(){return tg;}()) + (M0) : (function" ascii
    $s13 = "+ (function fpKr(){return kpgKr;}()) + (function Alus(){return Pb;}())]();var nnte = \"QEROM\";nnte = da(XOiXg, A);var tgqdr = " ascii
    $s14 = "+ (function Ej(){return QFGbn;}()) + (function fD(){return FwKTZ;}()) + (function V(){return OA;}()) + (function WiI(){return Ge" ascii
    $s15 = "on mX(){return (function P(){return D;}()) + (rR) + (function WlxNm(){return lgwbS;}()) + (function UxI(){return JoFYl;}()) + (k" ascii
    $s16 = " dBrZ;}()) + (function FW(){return nTu;}()) + (function k0(){return jNr;}()) + (function Z(){return oJjd;}()) + (function Ms(){r" ascii
    $s17 = "F;}()) + (function b(){return UNFED;}())]();while (k[(UG) + (function c(){return xdACg;}()) + (function OaTRH(){return O0;}())] " ascii
    $s18 = ";QH[(function Pd(){return a;}()) + (function Wc(){return FKZ;}()) + (function XG(){return q0;}())]();vN(N);nnte = \"\" + (functi" ascii
    $s19 = "urn lBqFX;}())](wflna());var CBa = new this[(function FRUSl(){return TNSXg;}()) + (function jUhUb(){return cGs;}())]();var XOiXg" ascii
    $s20 = " NAdw(){var CBa = new this[(function RLIAr(){return TNSXg;}()) + (cGs)]();var A = CBa[(function XOw(){return se;}()) + (function" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}