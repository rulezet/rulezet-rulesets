rule sig_20160721_03566576af04bdaeff7b288c4c2da320 {
  meta:
    description = "datamaliciousorder - file 20160721_03566576af04bdaeff7b288c4c2da320.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97d21bd68dd362b1cfd29ea7a10f7f5a8a3744cf73003bebfcc71282f05b4768"

  strings:
    $s1  = "    var UVx7 = WScript[CWr + Rk1 + Xu]((function Gx(){return ERz;}()) + Lo1 + Va5 + VBi5 + Dn + MXo + Vm + HCj4);" fullword ascii
    $s2  = "    var MXt6 = WScript[CWr + (function RCg(){return Rk1;}()) + Xu](FRx3 + YDm3 + Zu6(Lj6) + Dk + NFo);" fullword ascii
    $s3  = "function YQi(Qq9){return Qq9;};var PCy = \"e\" + \"\";" fullword ascii
    $s4  = "function Zu6(Rn2){return Rn2;};var NFo = \"nt\" + \"\";" fullword ascii
    $s5  = "function Ot(Qb){return Qb;};var OSq = \".e\" + \"\";" fullword ascii
    $s6  = "function PDq(OBw){return OBw;};var HNs7 = \"Data\" + \"\";" fullword ascii
    $s7  = "function PXr3(QBc4){return QBc4;};var ZWu3 = \"l\" + \"\";" fullword ascii
    $s8  = "function WQh(HXs){return HXs;};var ZAh = \"te\" + \"\";" fullword ascii
    $s9  = "var Yi=Wh + Hr + Nb + VTl0 + (function JIt0(){return GEf7;}());" fullword ascii
    $s10 = "function Re2(Oi){return Oi;};var Tl = \"le\" + \"\";" fullword ascii
    $s11 = "function Ac0(Uf){return Uf;};var Vb7 = \".b\" + \"\";" fullword ascii
    $s12 = "function Zv0(HZf9){return HZf9;};var Jg1 = \"e\" + \"\";" fullword ascii
    $s13 = "function Ir7(Ja, LFe2) {" fullword ascii
    $s14 = "ion TAh5(){return HCj4;}()))" fullword ascii
    $s15 = "function NIe1(HIj, LFe2)" fullword ascii
    $s16 = "    var VBl = MXt6[(function YWe(){return Gw0;}()) + LMz2 + BXk6 + (function Tp3(){return Dq1;}()) + DTq3](AHr1 + Jp5 + PDq(Sz8)" ascii
    $s17 = "   Ew1 = Cj[(function PAu1(){return Va;}()) + WRd9 + Re2(Tl)](LFe2, Mm, true)" fullword ascii
    $s18 = "    WFh4[(function UPo9(){return FCh;}()) + Yf + RBh4](LFe2, Iv);" fullword ascii
    $s19 = "    var VBl = MXt6[(function YWe(){return Gw0;}()) + LMz2 + BXk6 + (function Tp3(){return Dq1;}()) + DTq3](AHr1 + Jp5 + PDq(Sz8)" ascii
    $s20 = "    var Io1 = LCk[Pz + (function MEq3(){return NAb9;}()) + UAq6 + (function Lc(){return ZFy;}()) + Og7](QUm8, Rq);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}