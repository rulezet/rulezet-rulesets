rule sig_20160722_0924a48d49a07ea0aa2ba76cee13f359 {
  meta:
    description = "datamaliciousorder - file 20160722_0924a48d49a07ea0aa2ba76cee13f359.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "838ad87b5c2af12b7f6eca84dc1f31907649ffcac0f51ade3036a262073ae08f"

  strings:
    $s1  = "function Oe(Ll2){return Ll2;};var Kw6 = \"Run\" + \"\";" fullword ascii
    $s2  = "    var PPa = WScript[(function Wb(){return TCg6;}()) + PMp + DPr5](UDy1(Jp) + TYi + WPk4 + Xi0);" fullword ascii
    $s3  = "    var ESy2 = WScript[TCg6 + Ut2(PMp) + DPr5](QMj0 + (function COt8(){return TMi9;}()) + Ku + FHn7 + RPq8 + IWr8 + Ji1(Jx8));" fullword ascii
    $s4  = "function NJy4(VCg){return VCg;};var Al0 = \"Close\" + \"\";" fullword ascii
    $s5  = "function Hp5(XIf){return XIf;};var OZr = \"in\" + \"\";" fullword ascii
    $s6  = "function SHl6(Zy3){return Zy3;};function Qz7(MCp){return MCp;};var Bg2 = \"eam\" + \"\";" fullword ascii
    $s7  = "ion Fb(PSb5){return PSb5;};var Jx8 = \"t\" + \"\";" fullword ascii
    $s8  = "function Ji1(UJa9){return UJa9;};function UPs(Ob7){return Ob7;};function Rl0(BXw){return BXw;};function Kh(Mw){return Mw;};funct" ascii
    $s9  = "function Ut2(UNt9){return UNt9;};function YKz4(DTp){return DTp;};var DPr5 = \"ect\" + \"\";" fullword ascii
    $s10 = "function CJw2(Kc2){return Kc2;};var Bg20 = \"/\" + \"\";" fullword ascii
    $s11 = "function MXh5(YNg2){return YNg2;};var GUj = \"ite\" + \"\";" fullword ascii
    $s12 = "function Mg2(CYt){return CYt;};function ANv(YQr){return YQr;};var TXl = \"lue\" + \"\";" fullword ascii
    $s13 = "function UDy1(RWn){return RWn;};var Xi0 = \"m\" + \"\";" fullword ascii
    $s14 = "function LYq(Ai){return Ai;};var PSz4 = \"ument\" + \"\";" fullword ascii
    $s15 = "ction Wr2(Na7){return Na7;};var VLh = \"e\" + \"\";" fullword ascii
    $s16 = "function OMj7(VJs){return VJs;};function Ax(IHd6){return IHd6;};function Sx(YAu0){return YAu0;};function BRl(Rb){return Rb;};fun" ascii
    $s17 = "function OMj7(VJs){return VJs;};function Ax(IHd6){return IHd6;};function Sx(YAu0){return YAu0;};function BRl(Rb){return Rb;};fun" ascii
    $s18 = "function Rs(QIe, Hc4) {" fullword ascii
    $s19 = "function Ji1(UJa9){return UJa9;};function UPs(Ob7){return Ob7;};function Rl0(BXw){return BXw;};function Kh(Mw){return Mw;};funct" ascii
    $s20 = "function FQy(Nu, Hc4)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}