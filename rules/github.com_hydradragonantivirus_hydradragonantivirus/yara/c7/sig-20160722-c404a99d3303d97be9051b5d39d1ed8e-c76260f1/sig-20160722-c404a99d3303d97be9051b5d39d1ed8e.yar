rule sig_20160722_c404a99d3303d97be9051b5d39d1ed8e {
  meta:
    description = "datamaliciousorder - file 20160722_c404a99d3303d97be9051b5d39d1ed8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de0235f6ac509b306584b4a5bc05b7135098b585ce8c393a2641246db4444d84"

  strings:
    $s1  = "function VZg3(ELv){return ELv;};var Ad8 = \"Run\" + \"\";" fullword ascii
    $s2  = "    var Bn = WScript[Dv5 + Wy + (function ZSx(){return ACs;}()) + Vk(LIn5)](LLm5 + Nv + Ia7 + VFz + Sr7 + Ap);" fullword ascii
    $s3  = "    var Us8 = WScript[Dv5 + LCm1(Wy) + ORp9(ACs) + LIn5](WSb5 + Nm9 + Bl5 + Oj + FSh3 + Jr + Mg5 + DSa1 + (function De1(){return" ascii
    $s4  = "    var Us8 = WScript[Dv5 + LCm1(Wy) + ORp9(ACs) + LIn5](WSb5 + Nm9 + Bl5 + Oj + FSh3 + Jr + Mg5 + DSa1 + (function De1(){return" ascii
    $s5  = "function WJg(CYo){return CYo;};var VJz = \"lue\" + \"\";" fullword ascii
    $s6  = "function TNg(Ab){return Ab;};var KPu5 = \"Y2TTF\" + \"\";" fullword ascii
    $s7  = "function SJb2(WMb){return WMb;};function YFi6(Jf){return Jf;};var Qk = \"le\" + \"\";" fullword ascii
    $s8  = "function DBv7(Ao){return Ao;};var Ce5 = \"%/\" + \"\";" fullword ascii
    $s9  = "function Pg4(Ny6){return Ny6;};var SWk5 = \"ype\" + \"\";" fullword ascii
    $s10 = "function LCm1(An5){return An5;};function ORp9(Rn2){return Rn2;};function Vk(BTw){return BTw;};function AHs(BAz5){return BAz5;};v" ascii
    $s11 = "var Qp4=SIn7 + (function Hr8(){return Vl1;}()) + TNg(KPu5);" fullword ascii
    $s12 = "function HPe9(LSz){return LSz;};function Tb5(DCu3){return DCu3;};var Kt = \"ose\" + \"\";" fullword ascii
    $s13 = "function CYp7(LRj){return LRj;};var WBa1 = \"t\" + \"\";" fullword ascii
    $s14 = "function IXb3(TKw){return TKw;};var HPq8 = \"ine\" + \"\";" fullword ascii
    $s15 = "function ENl(VAw7){return VAw7;};var LOa = \"File\" + \"\";" fullword ascii
    $s16 = "function BXv5(ISk5){return ISk5;};var RBt = \"ell\" + \"\";" fullword ascii
    $s17 = "var v_binpath=Tv+WTs5+(function HIp4(){return Fs;}());" fullword ascii
    $s18 = "function LMq1(CEe, Sj)" fullword ascii
    $s19 = "function LCm1(An5){return An5;};function ORp9(Rn2){return Rn2;};function Vk(BTw){return BTw;};function AHs(BAz5){return BAz5;};v" ascii
    $s20 = "function Bn7(YWf0, Sj) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}