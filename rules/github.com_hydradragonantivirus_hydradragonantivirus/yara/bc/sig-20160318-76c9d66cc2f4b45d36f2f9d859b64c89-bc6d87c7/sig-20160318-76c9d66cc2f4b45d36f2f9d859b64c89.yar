rule sig_20160318_76c9d66cc2f4b45d36f2f9d859b64c89 {
  meta:
    description = "datamaliciousorder - file 20160318_76c9d66cc2f4b45d36f2f9d859b64c89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9684a646607ba0811d827cbf4690b8ddddd2f55b325dbd9716d6d911f0d1b6a9"

  strings:
    $s1  = "var cl = \"DZP!z4P\"[\"charAt\"](3);var CtGKe = \"ain\";var M0 = \" a\\x67\";var AwJe = \"\\x20try\";var JmmKG = \"e,\";var XdnL" ascii
    $s2  = "ViH(){return lkskc;}()) + (O0); mB = beQ(); yL = WScript[(function D(){return PlVt;}()) + (WaSUo) + (function d(){return cpT;}()" ascii
    $s3  = ")) + (function f(){return ua;}())](dkDA() * 10)};pnL = WScript[rSXkZ()]((B0) + (function koW(){return aazau;}()) + (function B1(" ascii
    $s4  = "on nzsi() {return WScript[(function U(){return PlVt;}()) + (function WBcJ(){return WaSUo;}()) + (function eoCK(){return cpT;}())" ascii
    $s5  = ")]();WScript[(function TZ(){return W0;}()) + (ua)](dkDA());var TmJ = new this[(function JdOxj(){return yJeK;}())]();var Q = TmJ[" ascii
    $s6  = "rn kKp;}()) + (function Fd(){return JFwPX;}()) + (function cxvB(){return VKBe;}())] < 4 ) {WScript[(function xBpv(){return W0;}(" ascii
    $s7  = ": (function bDaJ(){return LxG;}()) + (function jyt(){return ody;}()) + (RGLvS);}else{WScript.Echo((function HmAVD(){return XdnLy" ascii
    $s8  = "rn Q1;}())]();WScript[(function xms(){return W0;}()) + (ua)](dkDA());var TmJ = new this[(function kqi(){return yJeK;}())]();var " ascii
    $s9  = "{return gC;}()) + (function IY(){return MKb;}());};function Psdml(Kxk, yYLg){return Kxk - yYLg;};function rSXkZ(){return (functi" ascii
    $s10 = " 0; Guvro < dkDA() * 1; Guvro++){if (CBgXK() != 0){dYXtD = true;myWU = true;break;}}function kAVj() {return dYXtD && myWU;};if (" ascii
    $s11 = " + (function sD(){return BtOY;}())]((function UIkY(){return Gl;}()) + (function zshy(){return VbDo;}()) + (function cOMF(){retur" ascii
    $s12 = "r RGLvS = \"ng120eye6\"[\"charAt\"](3);var ody = \"3681\\x36\";var LxG = \"218\";var UoF = \"nwfLp7\"[\"charAt\"](2);var pZpyx =" ascii
    $s13 = "+ (function Anw(){return StQZd;}())) + (function DV(){return prK;}()) + (function zSoD(){return YLFvJ;}()) + (PVXR) + (function " ascii
    $s14 = "nction f0(){return PBwlf;}()) + (function fo(){return zGpW;}()) + (function oZBjq(){return t1;}()) + (function GqEa(){return RQo" ascii
    $s15 = "vZnXy = TmJ[(function wKNG(){return t;}()) + (OkB) + (Q0) + (function cqe(){return mpCK;}()) + (Q1)]();var LaOJj = \"oD\";LaOJj " ascii
    $s16 = "b;}()) + (function rdjU(){return K;}()) + (lpk)]((function r(){return QTlI;}()) + (taZmk) + (function FzrJW(){return JTjtg;}()) " ascii
    $s17 = "BGpEI);LaOJj = \"\" + (function dCQ(){return g0;}()) + (function AhTQ(){return rfPVO;}()) + (function S0(){return pfYf;}()) + (f" ascii
    $s18 = "(function H(){return t;}()) + (function JwTJ(){return OkB;}()) + (Q0) + (function palEj(){return mpCK;}()) + (function PG(){retu" ascii
    $s19 = "n BCk(){return t;}()) + (function eBI(){return OkB;}()) + (function h0(){return Q0;}()) + (function FMt(){return mpCK;}()) + (Q1" ascii
    $s20 = "){return AoGgT;}()), (rLSP) + (nZe) + (p) + (yfk) + (nSEr) + (OvVG) + (MYoA) + (function BEB(){return vDuvz;}()) + (function QtV" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}