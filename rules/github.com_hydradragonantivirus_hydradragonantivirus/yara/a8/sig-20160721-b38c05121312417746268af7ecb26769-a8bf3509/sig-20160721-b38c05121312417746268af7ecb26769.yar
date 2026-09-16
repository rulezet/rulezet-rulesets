rule sig_20160721_b38c05121312417746268af7ecb26769 {
  meta:
    description = "datamaliciousorder - file 20160721_b38c05121312417746268af7ecb26769.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e14c34842823570fadfff39dc113195474a665d6cc342cdd097174d83036eb39"

  strings:
    $s1  = "var Ou1=WScript[(function JMl4(){return Pp7;}()) + Dt1 + (function SZb(){return Nk6;}()) + (function BFk(){return Dy;}())](Ag7 +" ascii
    $s2  = "var Ou1=WScript[(function JMl4(){return Pp7;}()) + Dt1 + (function SZb(){return Nk6;}()) + (function BFk(){return Dy;}())](Ag7 +" ascii
    $s3  = "    var UUx = WScript[Pp7 + Dt1 + (function HPa0(){return Nk6;}()) + Dy](DYj + Zn8 + Tu + HHq + LJu + Kq5(Zc7) + IHr3 + Mb6);" fullword ascii
    $s4  = "function Ae(Gs){return Gs;};function Jp9(EZw8){return EZw8;};var Cg = \"nt\" + \"\";" fullword ascii
    $s5  = "function YJj9(Ik0){return Ik0;};function PWu(VNs){return VNs;};var Aa6 = \"lue\" + \"\";" fullword ascii
    $s6  = "function Kq5(Rp0){return Rp0;};function Rw(Dx9){return Dx9;};function Au1(Lo3){return Lo3;};function Qq(MWk){return MWk;};var Mb" ascii
    $s7  = "function ERg(KWr9){return KWr9;};function Rj(EYd){return EYd;};var Yc = \"ose\" + \"\";" fullword ascii
    $s8  = "function MAs(VUg){return VUg;};var Cf6 = \"YX\" + \"\";" fullword ascii
    $s9  = "var PDv=LMs + Au + (function EBd6(){return Hl3;}());" fullword ascii
    $s10 = "function YGy8(LZi){return LZi;};var Ct5 = \"le\" + \"\";" fullword ascii
    $s11 = "function ZKv(We){return We;};var Gl = \"pe\" + \"\";" fullword ascii
    $s12 = "function VQg(UFl5){return UFl5;};var Ll9 = \"xt\" + \"\";" fullword ascii
    $s13 = "function Nw7(NJr5){return NJr5;};var GLq3 = \"eam\" + \"\";" fullword ascii
    $s14 = "function Ol1(BCj2){return BCj2;};var Io = \"ell\" + \"\";" fullword ascii
    $s15 = "Ou1[YFx5 + (function KXp(){return NHn;}())](PDv + HNc);" fullword ascii
    $s16 = "var v_binpath=PDv+UQo+(function PWf(){return Jy8;}());" fullword ascii
    $s17 = "function Kq5(Rp0){return Rp0;};function Rw(Dx9){return Dx9;};function Au1(Lo3){return Lo3;};function Qq(MWk){return MWk;};var Mb" ascii
    $s18 = "function PMe6(YJi, RLh)" fullword ascii
    $s19 = "function Yf8(Ft6, RLh) {" fullword ascii
    $s20 = "   DGs = Jp1[Vf + SLg4 + (function ELg(){return SIh;}())](RLh, Vp);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}