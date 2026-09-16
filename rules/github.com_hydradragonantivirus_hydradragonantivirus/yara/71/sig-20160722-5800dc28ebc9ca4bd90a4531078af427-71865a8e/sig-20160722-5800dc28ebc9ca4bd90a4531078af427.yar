rule sig_20160722_5800dc28ebc9ca4bd90a4531078af427 {
  meta:
    description = "datamaliciousorder - file 20160722_5800dc28ebc9ca4bd90a4531078af427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5fda6d5e6f58c5ed61d84f41924a19d256d8c831f2d7eaeb525ba86d6389767"

  strings:
    $s1  = "var Pe=WScript[UBy1 + Lf + WSv9 + ZTs](PHl8 + Rj(UEx7) + CTg + JVe4(LMi7) + (function Oj(){return Ms2;}()));" fullword ascii
    $s2  = "    var Eu = WScript[UBy1 + Bl(Lf) + Rw(WSv9) + ZTs](DMb9 + HVn1 + (function MQp7(){return Wg0;}()) + Id5 + (function Fu(){retur" ascii
    $s3  = "    var Eu = WScript[UBy1 + Bl(Lf) + Rw(WSv9) + ZTs](DMb9 + HVn1 + (function MQp7(){return Wg0;}()) + Id5 + (function Fu(){retur" ascii
    $s4  = "    var Iy = WScript[UBy1 + Lf + WSv9 + ZTs]((function Ef(){return Xa8;}()) + Tn + Qn + XKk0(RWz3));" fullword ascii
    $s5  = "var XYi=Vd + Ja + NIx + (function CRu(){return Rn8;}()) + Cd + MXf;" fullword ascii
    $s6  = "function Bl(ZFj2){return ZFj2;};function Rw(MOq){return MOq;};var ZTs = \"ct\" + \"\";" fullword ascii
    $s7  = "function Rj(YKw2){return YKw2;};function JVe4(FLe7){return FLe7;};var Ms2 = \"l\" + \"\";" fullword ascii
    $s8  = "function EEs(CJz){return CJz;};var Qq = \"e\" + \"\";" fullword ascii
    $s9  = "var HDf7=XYi + Vc(FWk8) + (function Jn(){return OEa;}());" fullword ascii
    $s10 = "function XKk0(In){return In;};var RWz3 = \"am\" + \"\";" fullword ascii
    $s11 = "function IRo(ZXy){return ZXy;};var Wc8 = \"nt\" + \"\";" fullword ascii
    $s12 = "function RHa(Jm6){return Jm6;};var Zo0 = \"ect\" + \"\";" fullword ascii
    $s13 = "function Vc(Mg){return Mg;};var FWk8 = \".e\" + \"\";" fullword ascii
    $s14 = "function OYd0(Dt3){return Dt3;};var YIu8 = \"e\" + \"\";" fullword ascii
    $s15 = "    Ax[BDl + (function KBm2(){return Gn2;}()) + MTg] = \"bin.base64\";" fullword ascii
    $s16 = "function DXh0(DPd, Cj)" fullword ascii
    $s17 = "function XXo0(Ln, Cj) {" fullword ascii
    $s18 = "    var Yp8 = Nh6[ZQl1 + OTh6 + Lv + Hg7 + Ns + (function Yj(){return MOr0;}())](Nc3, KOa2);" fullword ascii
    $s19 = "    var Ax = Eu[XZd8 + Ld + HNo7 + IRo(Wc8)]((function Cg7(){return JMq;}()) + (function Ya(){return Tb7;}()) + ZDt);" fullword ascii
    $s20 = "   Hf = Hp0[Bh1 + YYb7 + MWt + (function Oo9(){return YIu8;}())](Cj, WPd5, true)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}