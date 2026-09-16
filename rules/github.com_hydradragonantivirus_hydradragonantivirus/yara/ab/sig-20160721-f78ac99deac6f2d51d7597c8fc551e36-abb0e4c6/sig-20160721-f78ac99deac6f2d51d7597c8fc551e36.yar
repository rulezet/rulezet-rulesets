rule sig_20160721_f78ac99deac6f2d51d7597c8fc551e36 {
  meta:
    description = "datamaliciousorder - file 20160721_f78ac99deac6f2d51d7597c8fc551e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cdc112e990640a331470b86cd99da57bc9d476785f6aab4cf851a7d1badfae5"

  strings:
    $s1  = "var WNc=WScript[Nr1 + UVw9 + ETw4 + Rf](VPv6 + UBo + (function Fh(){return Py0;}()));" fullword ascii
    $s2  = "function WNh(Lv){return Lv;};var DIt1 = \"Run\" + \"\";" fullword ascii
    $s3  = "    var PZs3 = WScript[Nr1 + Uc3(UVw9) + ETw4 + (function EZy2(){return Rf;}())](SQb4 + Kb(Wt7) + (function Qv(){return PMw6;}()" ascii
    $s4  = "    var PZs3 = WScript[Nr1 + Uc3(UVw9) + ETw4 + (function EZy2(){return Rf;}())](SQb4 + Kb(Wt7) + (function Qv(){return PMw6;}()" ascii
    $s5  = "    var Xh = WScript[Nr1 + UVw9 + ETw4 + Rf](Fh5 + (function Yq(){return TBw;}()) + Zh4(Ao) + JJu2);" fullword ascii
    $s6  = "function Nm4(ARj){return ARj;};var GKg3 = \".b\" + \"\";" fullword ascii
    $s7  = "function Jn(JTp5){return JTp5;};var TZs = \"xe\" + \"\";" fullword ascii
    $s8  = ") + (function Ew(){return YBh3;}()) + LDn1 + (function XQs(){return Bl0;}()));" fullword ascii
    $s9  = "function Uc3(Tx){return Tx;};var Rf = \"bject\" + \"\";" fullword ascii
    $s10 = "var Ue=YKw0 + PNv1 + PCw + Fu + (function Cy6(){return Up;}());" fullword ascii
    $s11 = "function GJl5(Jq4){return Jq4;};var SQv2 = \"text\" + \"\";" fullword ascii
    $s12 = "function EGh5(TLf){return TLf;};var IGj7 = \"m\" + \"\";" fullword ascii
    $s13 = "var Nz8=Ue + (function Fx2(){return Iv1;}()) + Jn(TZs);" fullword ascii
    $s14 = "function HGt8(NYa5){return NYa5;};function Jl(Rm2){return Rm2;};var Iu7 = \"le\" + \"\";" fullword ascii
    $s15 = "function Zh4(VTe5){return VTe5;};var JJu2 = \"eam\" + \"\";" fullword ascii
    $s16 = "function Ed(Gf4){return Gf4;};function CUk(Bz3){return Bz3;};var ZXm1 = \"ose\" + \"\";" fullword ascii
    $s17 = "var YKw0=WNc.ExpandEnvironmentStrings(Cq + (function MVs5(){return Fx4;}()));" fullword ascii
    $s18 = "function Kb(Aq2){return Aq2;};var Bl0 = \"t\" + \"\";" fullword ascii
    $s19 = "function JJf1(Bu1){return Bu1;};var Fi = \"Data\" + \"\";" fullword ascii
    $s20 = "function ZRp5(OSq9){return OSq9;};var EWx0 = \"t\" + \"\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}