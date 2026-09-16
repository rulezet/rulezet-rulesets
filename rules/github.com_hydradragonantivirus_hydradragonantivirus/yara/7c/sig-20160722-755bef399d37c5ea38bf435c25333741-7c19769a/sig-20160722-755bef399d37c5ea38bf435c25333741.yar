rule sig_20160722_755bef399d37c5ea38bf435c25333741 {
  meta:
    description = "datamaliciousorder - file 20160722_755bef399d37c5ea38bf435c25333741.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "299a54f752cc41e3f0dceeb8547996adf53ffea1c94bdf44b046dc8a6e737767"

  strings:
    $s1  = "var CFm2=WScript[BZl0(TWb) + Sh5 + Pf9](Zm + (function Ce(){return Vm;}()) + YSh + THu + Bw + JZl);" fullword ascii
    $s2  = "    var Un = WScript[(function Nr(){return TWb;}()) + Sh5 + Pf9](YKr + Nf + Tf + VJq + RXn + Mm0(Mh));" fullword ascii
    $s3  = "    var KSl = WScript[TWb + Sh5 + Pf9](GPh9 + (function Wh(){return DTo;}()) + Qp);" fullword ascii
    $s4  = "function BZl0(Hx7){return Hx7;};var Pf9 = \"ect\" + \"\";" fullword ascii
    $s5  = "function Yy(Il){return Il;};var Ju7 = \"e\" + \"\";" fullword ascii
    $s6  = "function Kw(ADi9){return ADi9;};var Kl = \"BikJ\" + \"\";" fullword ascii
    $s7  = "function CIt5(Cj9){return Cj9;};var Ns = \"ine\" + \"\";" fullword ascii
    $s8  = "function Pi(YPh){return YPh;};function RTz(Em4){return Em4;};function Io(RAz9){return RAz9;};function Vm4(Vz){return Vz;};var Dw" ascii
    $s9  = "var OYz5=PVx4 + Dx4 + (function KMo3(){return Fm6;}());" fullword ascii
    $s10 = "function Pi0(GSh){return GSh;};var PVc0 = \"nt\" + \"\";" fullword ascii
    $s11 = "function Mm0(Be2){return Be2;};var Mh = \"ent\" + \"\";" fullword ascii
    $s12 = "function Vg(Zc5){return Zc5;};var XKs9 = \"xt\" + \"\";" fullword ascii
    $s13 = "function DKs8(Ld1){return Ld1;};var AZw = \" 321\" + \"\";" fullword ascii
    $s14 = "var v_binpath=OYz5+(function Ss0(){return TXm;}())+Hl4;" fullword ascii
    $s15 = "    IEa[(function Sz6(){return Gh;}()) + XDy] = \"bin.base64\";" fullword ascii
    $s16 = "function Pi(YPh){return YPh;};function RTz(Em4){return Em4;};function Io(RAz9){return RAz9;};function Vm4(Vz){return Vz;};var Dw" ascii
    $s17 = "function EUi2(Pm1, Lg) {" fullword ascii
    $s18 = "function Uj9(ZMp, Lg)" fullword ascii
    $s19 = "   QCf1 = Ne[NLk + (function YRa5(){return YNn;}()) + SEh2](Lg, PEy1, true)" fullword ascii
    $s20 = "    var RSs3 = Ks[ELo7 + (function EPj1(){return SBs2;}())](Pm1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}