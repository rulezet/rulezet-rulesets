rule sig_20160722_e86df21747e6610df7fd96a56b25ff62 {
  meta:
    description = "datamaliciousorder - file 20160722_e86df21747e6610df7fd96a56b25ff62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eecd7905169d502afca2c4529ccf1e1032074581992e3cdaa70a3f50995596b"

  strings:
    $s1  = "    var BHh8 = WScript[Mt0 + Ga9 + Kg4](Fj7 + Ge2 + (function AJp(){return GIg0;}()) + ADh9 + Dk8 + Vu);" fullword ascii
    $s2  = "function Xx(PFh){return PFh;};function Jh(Ag8){return Ag8;};var QXc = \"ne\" + \"\";" fullword ascii
    $s3  = "function OIl(CDd7){return CDd7;};var Ir = \"ile\" + \"\";" fullword ascii
    $s4  = "function Mp2(GIe){return GIe;};var Pu9 = \"4Data\" + \"\";" fullword ascii
    $s5  = "function LYg0(WZt3){return WZt3;};var Kg4 = \"ct\" + \"\";" fullword ascii
    $s6  = "function WDl(KTj){return KTj;};var LTd5 = \"All\" + \"\";" fullword ascii
    $s7  = "function VCy(Ex1){return Ex1;};var Di0 = \"e\" + \"\";" fullword ascii
    $s8  = "function Yw9(BEj){return BEj;};function Pj6(Um){return Um;};var HRn = \"le\" + \"\";" fullword ascii
    $s9  = "function Hp1(AUw9){return AUw9;};var Qw6 = \"bject\" + \"\";" fullword ascii
    $s10 = "function Lb(TJt){return TJt;};var JHj2 = \"t\" + \"\";" fullword ascii
    $s11 = "function Nn(Rq8){return Rq8;};var YHo = \"am\" + \"\";" fullword ascii
    $s12 = "function Ql1(DDr3){return DDr3;};var ZUe = \"ile\" + \"\";" fullword ascii
    $s13 = "function Kt7(Ek, Io)" fullword ascii
    $s14 = "function Pe9(Pi7, Io) {" fullword ascii
    $s15 = "    XMr[(function BFy(){return RHi3;}()) + (function Bo(){return TZj;}())]();" fullword ascii
    $s16 = "    XMr[Ji6](Id5[OHp2 + ZBh8 + (function LTn(){return Vg;}()) + Af + LNk5 + CHz]);" fullword ascii
    $s17 = "   Qy7 = YXj[Xy4 + (function YOe(){return MGv;}()) + VRx4 + OIl(Ir)](Io, HCd0, true)" fullword ascii
    $s18 = "    var Id5 = BHh8[WAa5 + ORi3 + (function Bs(){return NKm;}()) + (function Zs(){return CFk3;}())](Db3 + Mp2(Pu9));" fullword ascii
    $s19 = "    Id5[(function WXt9(){return Zi8;}()) + Lb(JHj2)] = DQf7[Uw8 + WDl(LTd5)]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}