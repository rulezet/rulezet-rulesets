rule sig_20160722_aa2f662f02564eab68310c5bb4cffb64 {
  meta:
    description = "datamaliciousorder - file 20160722_aa2f662f02564eab68310c5bb4cffb64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1155118585c6eaf61f987e8e00b2286b20bd9b3488c3d5c0e170a4992054c99"

  strings:
    $s1  = "    var EGh = WScript[Rn1 + Xp + YVa1]((function Yt(){return Li5;}()) + Nm + (function Mf(){return Ey7;}()) + HUr7);" fullword ascii
    $s2  = "    var Lp1 = WScript[Rn1 + Xp + INn6(YVa1)](NWp7 + (function DPj(){return Jh4;}()) + BIf4 + Qe + Hz + Eo + Ma + XOs);" fullword ascii
    $s3  = "function YCi(KLk){return KLk;};var XOs = \"ject\" + \"\";" fullword ascii
    $s4  = "var DGs=Ze8 + Vy3 + Cr(Un) + KFf(Ng7) + (function JYq(){return IVj;}());" fullword ascii
    $s5  = "function Ro(Ku20){return Ku20;};function Ks3(OFg1){return OFg1;};var PCl = \"lue\" + \"\";" fullword ascii
    $s6  = "function INn6(Mr){return Mr;};var YVa1 = \"ect\" + \"\";" fullword ascii
    $s7  = "function Cr(WKm9){return WKm9;};function KFf(LYt){return LYt;};var IVj = \"m\" + \"\";" fullword ascii
    $s8  = "Nl[(function ECj1(){return ZQs;}()) + Ir5](TUg + Iz);" fullword ascii
    $s9  = "function Ve6(ZKx2){return ZKx2;};var HHi = \"e\" + \"\";" fullword ascii
    $s10 = "function FZz(BMc){return BMc;};var Tx3 = \"ine\" + \"\";" fullword ascii
    $s11 = "function Se(JKb9){return JKb9;};var ZAa7 = \"4Data\" + \"\";" fullword ascii
    $s12 = "function DMs2(VPw9){return VPw9;};function CNa1(CBq9){return CBq9;};var JDl = \"ile\" + \"\";" fullword ascii
    $s13 = "function La(Ql9){return Ql9;};var ZVc7 = \"MP%/\" + \"\";" fullword ascii
    $s14 = "function Tm3(Sq){return Sq;};var HTu = \"xe\" + \"\";" fullword ascii
    $s15 = "function Jg(Sa3){return Sa3;};function VJu(Bo2){return Bo2;};var Sm9 = \"ite\" + \"\";" fullword ascii
    $s16 = "function YTx(DUo5){return DUo5;};var Gw0 = \"oFile\" + \"\";" fullword ascii
    $s17 = "function Ku2(HWo, Ht)" fullword ascii
    $s18 = "function APb2(OUr, Ht) {" fullword ascii
    $s19 = "   BOr = new ActiveXObject((function RTq(){return NWp7;}()) + Jh4 + YCi(BIf4) + (function TFs2(){return Qe;}()) + Hz + Eo + Ma +" ascii
    $s20 = "    Qw2[Js6 + (function Tz(){return Sx7;}())] = Zw[Sp + Ta6]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}