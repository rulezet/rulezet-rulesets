rule sig_20160721_4a812bb744acf0f563341fe4ad0c5d44 {
  meta:
    description = "datamaliciousorder - file 20160721_4a812bb744acf0f563341fe4ad0c5d44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0183a9b1409db9e101707c446019d6f2b6741e8f8303eb34b66cfd00c1c86621"

  strings:
    $s1  = "var Kh3=WScript[Mp2 + VJx2 + (function Nd2(){return Py;}())](Zd6 + CGg1 + WRe(VQc) + Mn6);" fullword ascii
    $s2  = "    var ILt = WScript[Mp2 + VJx2 + Py](GXh + Ms + (function FEd2(){return YQq;}()) + PTj5 + JHz3 + Bp3);" fullword ascii
    $s3  = "    var Oo = WScript[Mp2 + (function Ez6(){return VJx2;}()) + Py](Qk + (function ADt3(){return QHz;}()) + Ue7 + Cd6 + OPj(Sk2));" ascii
    $s4  = "var MBo7=CTl4 + FKa8 + Zw + WZb + ZNx + (function Fg4(){return Eh;}());" fullword ascii
    $s5  = "function WRe(AGp4){return AGp4;};var Mn6 = \"l\" + \"\";" fullword ascii
    $s6  = "function Ma(QIl){return QIl;};var HWf = \"Value\" + \"\";" fullword ascii
    $s7  = "function Vl7(HSa5){return HSa5;};var CFf = \"l\" + \"\";" fullword ascii
    $s8  = "function WIh0(IUd3){return IUd3;};function Py1(Ks6){return Ks6;};var Mw = \"bject\" + \"\";" fullword ascii
    $s9  = "function TPf(Yj1){return Yj1;};var SUs = \"Close\" + \"\";" fullword ascii
    $s10 = "function OPv(Sn){return Sn;};var JQt5 = \"e\" + \"\";" fullword ascii
    $s11 = "function Mo2(Qj){return Qj;};var JIp3 = \"le\" + \"\";" fullword ascii
    $s12 = "function OPj(MZc){return MZc;};var Sk2 = \"m\" + \"\";" fullword ascii
    $s13 = "function Vn1(EEc){return EEc;};var Vj = \"ite\" + \"\";" fullword ascii
    $s14 = "function Na1(Wg2){return Wg2;};function Vc6(SMn7){return SMn7;};var Vd2 = \"t\" + \"\";" fullword ascii
    $s15 = "    Wk[ENg2 + (function TTw9(){return PGi3;}()) + JNx] = \"bin.base64\";" fullword ascii
    $s16 = "function Ej3(NQq6, Ys)" fullword ascii
    $s17 = "function Xy(KHq9, Ys) {" fullword ascii
    $s18 = "   QFq1 = Id4[(function WCk(){return Fn;}()) + Mo2(TZy) + JIp3](Ys, Ym, true)" fullword ascii
    $s19 = "   QFq1 = Id4[Fn + (function UHs8(){return TZy;}()) + JIp3](Ys, KMz);" fullword ascii
    $s20 = "   Id4 = new ActiveXObject(Qt8 + He + JJi + SBi9 + ZXc + Py1(YTc4) + (function COs(){return PCx6;}()) + Mw)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}