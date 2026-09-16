rule sig_20160722_503114b2e9079b833ac7d3109536a357 {
  meta:
    description = "datamaliciousorder - file 20160722_503114b2e9079b833ac7d3109536a357.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17e4a46825c394f598f6b377bd20d00e123aee50b375244c1f2990daf0cec0d3"

  strings:
    $s1  = "var Fa1=WScript[(function MDb2(){return EOc;}()) + Sg + VWd1 + Qs3 + YSz9](COt + (function CLb4(){return NPl9;}()) + OKn + OCn);" ascii
    $s2  = "    var Dn = WScript[VLd(EOc) + Sg + (function Fj0(){return VWd1;}()) + Qs3 + YSz9](HXx + CUr7 + QVt(We));" fullword ascii
    $s3  = "    var FUa2 = WScript[Bk(EOc) + Sg + VWd1 + Qs3 + YSz9](Gj0 + RCt + FVg + (function PUk8(){return Pf3;}()) + (function St(){ret" ascii
    $s4  = "    var FUa2 = WScript[Bk(EOc) + Sg + VWd1 + Qs3 + YSz9](Gj0 + RCt + FVg + (function PUk8(){return Pf3;}()) + (function St(){ret" ascii
    $s5  = "function JFk(Ge0){return Ge0;};var VSf = \"ment\" + \"\";" fullword ascii
    $s6  = "function Hu(NRz){return NRz;};function ZXc(PUb9){return PUb9;};var HNz = \"oFile\" + \"\";" fullword ascii
    $s7  = "function Bk(JXq4){return JXq4;};function VLd(HPp){return HPp;};var YSz9 = \"t\" + \"\";" fullword ascii
    $s8  = "var Tv3=Fa1.ExpandEnvironmentStrings(Nk7 + (function JHz(){return USs;}()));" fullword ascii
    $s9  = "function QVt(BJt){return BJt;};var We = \"eam\" + \"\";" fullword ascii
    $s10 = "function Yl3(Cr8){return Cr8;};function Ae0(ZEk1){return ZEk1;};var Io = \"1\" + \"\";" fullword ascii
    $s11 = "function ETx7(BAx1){return BAx1;};var Xz1 = \"e\" + \"\";" fullword ascii
    $s12 = "urn ZQc;}()) + MYm + (function OKi8(){return NLz;}()) + IIw5);" fullword ascii
    $s13 = "function Zo7(SYs3){return SYs3;};function SKc(Wo7){return Wo7;};function Yb(Wd0){return Wd0;};var IIw5 = \"ect\" + \"\";" fullword ascii
    $s14 = "function JJk(SBq){return SBq;};var Tg = \"xe\" + \"\";" fullword ascii
    $s15 = "function YXw1(HOw){return HOw;};var XNo = \"le\" + \"\";" fullword ascii
    $s16 = "var v_binpath=Ro0+UTf+(function LBd(){return PIl;}());" fullword ascii
    $s17 = "function Au(CHw4, Gp) {" fullword ascii
    $s18 = "function RIi(Da9, Gp)" fullword ascii
    $s19 = "    Dn[Mq3 + KSh6 + (function Oe7(){return Xz1;}())]();" fullword ascii
    $s20 = "    Dn[(function ZMz(){return QZr;}()) + Zl](MCu[Lb3 + (function Uq1(){return JKl0;}()) + Pm4 + Ih]);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}