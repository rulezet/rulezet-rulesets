rule sig_20160722_a74a99b96439670082144f86c170eafc {
  meta:
    description = "datamaliciousorder - file 20160722_a74a99b96439670082144f86c170eafc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca53d07adfcfd55c01ac3d4d3387262b589839c1c11071a744f127c2426f4efb"

  strings:
    $s1  = "var Lz=WScript[HQk + Zd + Sr8](Gi3 + (function Qk(){return RKy5;}()) + AEp9(QUv9) + WDd);" fullword ascii
    $s2  = "    var Kk6 = WScript[HQk + Zd + Sr8](VYu + Bt4(JTu3) + Em(Mo) + (function Tg0(){return Im;}()) + FHz);" fullword ascii
    $s3  = "    var Rf9 = WScript[HXr(HQk) + Zd + (function Wn5(){return Sr8;}())](Rf4(Om) + DNc + (function LVt(){return Gl2;}()) + FCr);" fullword ascii
    $s4  = "    var HGc4 = WScript[HQk + HVs(Zd) + (function BJd(){return Sr8;}())](Ng + QNj + Ng5 + Cj + CSv + Hb(SCm) + RDy6);" fullword ascii
    $s5  = "function Lu0(Hb0){return Hb0;};var IKw1 = \"e\" + \"\";" fullword ascii
    $s6  = "function Bt4(JSy){return JSy;};function Em(Eu6){return Eu6;};var FHz = \"ent\" + \"\";" fullword ascii
    $s7  = "function Gc6(Js1){return Js1;};function Yl9(Yq7){return Yq7;};var PPc = \"Close\" + \"\";" fullword ascii
    $s8  = "function QYj(Wa2){return Wa2;};var INw = \"le\" + \"\";" fullword ascii
    $s9  = "var Af=Dx5 + YHd + (function NOt(){return LSe9;}());" fullword ascii
    $s10 = "function RFx(NSt){return NSt;};var VYq = \"ile\" + \"\";" fullword ascii
    $s11 = "function Uj(Iy){return Iy;};function YAm3(Nr4){return Nr4;};var Bt9 = \"ream\" + \"\";" fullword ascii
    $s12 = "function AEp9(FQr8){return FQr8;};var WDd = \"ll\" + \"\";" fullword ascii
    $s13 = "function Rf4(ATv){return ATv;};var FCr = \"ream\" + \"\";" fullword ascii
    $s14 = "function HVs(Ie){return Ie;};function HXr(Am){return Am;};var Sr8 = \"bject\" + \"\";" fullword ascii
    $s15 = "function Hb(ONi){return ONi;};function Dl5(ODm){return ODm;};var RDy6 = \"ject\" + \"\";" fullword ascii
    $s16 = "function At(Gd4){return Gd4;};var Up0 = \"Data\" + \"\";" fullword ascii
    $s17 = "var Or9=Lz.ExpandEnvironmentStrings(Wf + VBb1 + (function Qs(){return AYa;}()));" fullword ascii
    $s18 = "    EBa1[(function Me3(){return Vp0;}()) + Qn4] = \"bin.base64\";" fullword ascii
    $s19 = "function Yn(GPf, Yj) {" fullword ascii
    $s20 = "function Ni2(Zm, Yj)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}