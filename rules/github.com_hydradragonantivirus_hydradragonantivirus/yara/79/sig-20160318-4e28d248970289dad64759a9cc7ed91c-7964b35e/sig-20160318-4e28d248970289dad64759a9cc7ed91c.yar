rule sig_20160318_4e28d248970289dad64759a9cc7ed91c {
  meta:
    description = "datamaliciousorder - file 20160318_4e28d248970289dad64759a9cc7ed91c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acededb8f9e6008aa033e4621e27fb081db870251012ae3ec826084068a2cf5b"

  strings:
    $s1  = "var tfb = \"\\x21\";var Bn = \"n\";var HR = \"\\x20\\x61g\\x61\\x69\";var t0 = \",\\x20\\x74\\x72\\x79\";var DWl = \"lea\\x73e\"" ascii
    $s2  = "UP = function Qq() {return WScript[(Ds) + (function UpSC(){return s;}()) + (function BUf(){return cWrOd;}()) + (function OHykH()" ascii
    $s3  = "RVo;}()) + (function xWFzf(){return NBZd;}())](oMQ() * 10)};xGAx = WScript[Cmpal()]((ZYk) + (function zzwV(){return O0;}()) + (s" ascii
    $s4  = "}())]();WScript[(function znXlt(){return RVo;}()) + (function Cf(){return NBZd;}())](oMQ());var vX = new this[(function la(){ret" ascii
    $s5  = "ction l0(){return Elfv;}()) + (F) + (D);}else{WScript.Echo((function Er(){return koFt;}()) + (function GWDX(){return DWl;}()) + " ascii
    $s6  = "eturn xTUJc;}()) + (function Oek(){return dpzMe;}()) + (function dV(){return CLRW;}())] < 4 ) {WScript[(function oqAMP(){return " ascii
    $s7  = "turn dt;}()) + (function Utlk(){return XA;}()); myu = NyZ(); WIBHh = WScript[(function vJZI(){return Ds;}()) + (function xG(){re" ascii
    $s8  = "WZS(){return boxAi;}());};function OtCYF(Ahri, Fco){return Ahri - Fco;};function Cmpal(){return (function WsOw(){return Ds;}()) " ascii
    $s9  = ") + (function gINmZ(){return DVPz;}()) + (bcABQ) + (function tZSw(){return hSkFM;}())]();WScript[(function ho(){return RVo;}()) " ascii
    $s10 = "vy(){return Bedzq;}()) + (function f(){return slUXs;}())]);xGAx[(function C0(){return Ux;}()) + (q) + (function pE(){return Upel" ascii
    $s11 = "iaE = false;for (var PsC = 0; PsC < oMQ() * 1; PsC++){if (ON() != 0){REM = true;BiaE = true;break;}}function mGjf() {return REM " ascii
    $s12 = "rn YlPC;}()) + (VHKao) + (function qMG(){return GYADZ;}()) + (function CHKGw(){return ZwlxH;}()) + (function wIX(){return Nq;}()" ascii
    $s13 = "on mvSh(){return qU;}()) + (function TMLQM(){return aXIEh;}()) + (function BEL(){return qk;}()) + (function TSIuj(){return T;}()" ascii
    $s14 = "M;}())] = 0;xGAx[(function Ne(){return sxmut;}()) + (QTrS) + (function Lo(){return rWJl;}())](pmC, 2 );xGAx[(function ppgES(){re" ascii
    $s15 = "+ (function jwMn(){return s;}()) + (function xgUC(){return cWrOd;}()) + (function sOmGc(){return X;}());};function oMQ(){return " ascii
    $s16 = "22;};function ON(){var vX = new this[(function YyLk(){return Ay;}()) + (function oYsQ(){return vKibW;}())]();var nH = vX[(functi" ascii
    $s17 = "ym)](Pd, 0, 0);};function NyZ(){return (function qe(){return ksx;}()) + (function NAnL(){return yIAEx;}()) + (LFgV) + (function " ascii
    $s18 = ") + (function Lyrn(){return MzZ;}()), false);WIBHh[(function sqJR(){return egvmK;}())]();while (WIBHh[(gqdBp) + (function RR(){r" ascii
    $s19 = "){return HcO;}()) + (yfp) + (function A(){return Z0;}()) + (RPQn) + (function jXlt(){return IMmIM;}()) + (function tNrW(){return" ascii
    $s20 = "(function cSs(){return t0;}()) + (function oDBF(){return HR;}()) + (function aW0(){return Bn;}()) + (function tsFU(){return tfb;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}