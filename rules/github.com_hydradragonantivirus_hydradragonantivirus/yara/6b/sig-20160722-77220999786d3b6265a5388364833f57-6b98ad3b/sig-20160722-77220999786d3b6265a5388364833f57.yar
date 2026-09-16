rule sig_20160722_77220999786d3b6265a5388364833f57 {
  meta:
    description = "datamaliciousorder - file 20160722_77220999786d3b6265a5388364833f57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7beec947008b3b3b02d5c96983babdba9a408935ea480fc01ba999a8109f1ce2"

  strings:
    $s1  = "var Rj=WScript[Ss + Bu8 + (function Ga(){return Ci7;}()) + St7](Sw + GXe2(Ba6) + CGc8 + ULf2);" fullword ascii
    $s2  = "    var Zp5 = WScript[Ss + Bu8 + Ci7 + St7]((function LKo4(){return DUs;}()) + Sy0 + AUx9 + CPe + BYs(IXx7) + Od6 + (function SH" ascii
    $s3  = "    var Zp5 = WScript[Ss + Bu8 + Ci7 + St7]((function LKo4(){return DUs;}()) + Sy0 + AUx9 + CPe + BYs(IXx7) + Od6 + (function SH" ascii
    $s4  = "function KBz(Go9){return Go9;};var St7 = \"t\" + \"\";" fullword ascii
    $s5  = "var Yf4=Rj.ExpandEnvironmentStrings(URq + (function Jh2(){return KMn5;}()) + Kw4(YNc));" fullword ascii
    $s6  = "var Cs3=Jc1 + HEz + (function DAt1(){return Yy0;}());" fullword ascii
    $s7  = "var Jc1=Yf4 + KDl2(Jq) + Nx + (function SQy(){return Pk9;}()) + (function Ie0(){return Bw;}());" fullword ascii
    $s8  = "function Je(YRy){return YRy;};var PMo5 = \"ine\" + \"\";" fullword ascii
    $s9  = "function Io6(Ym){return Ym;};var Nq = \"m\" + \"\";" fullword ascii
    $s10 = "function Kw4(IXa){return IXa;};var YNc = \"P%/\" + \"\";" fullword ascii
    $s11 = "function GXe2(EFk1){return EFk1;};var ULf2 = \"hell\" + \"\";" fullword ascii
    $s12 = "function Uw8(Ay3){return Ay3;};var Tx = \"e\" + \"\";" fullword ascii
    $s13 = "function KDl2(POk){return POk;};var Bw = \"W7\" + \"\";" fullword ascii
    $s14 = "function Hx(Mh){return Mh;};var Ep3 = \"e\" + \"\";" fullword ascii
    $s15 = "function HEr0(Yl){return Yl;};var Lp9 = \"t\" + \"\";" fullword ascii
    $s16 = "function BYs(RYo){return RYo;};var Mi3 = \"t\" + \"\";" fullword ascii
    $s17 = "function DOy(Xh){return Xh;};function BMm3(Ri){return Ri;};var Wb8 = \"le\" + \"\";" fullword ascii
    $s18 = "    Xr6[Ll + (function DIv9(){return Sb;}()) + Uw8(Tx)] = \"bin.base64\";" fullword ascii
    $s19 = "function Wb(UZv){return UZv;};var CAc3 = \"se\" + \"\";" fullword ascii
    $s20 = "function SKp(Ox3, EGx)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}