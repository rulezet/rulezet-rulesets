rule sig_20160722_fcd0120e6c24d965c77e2faa04cf93eb {
  meta:
    description = "datamaliciousorder - file 20160722_fcd0120e6c24d965c77e2faa04cf93eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "155a7a804ea1127a4d6b4b31c70b3e1c315dbed7251f5874fe7d5fa28092d531"

  strings:
    $s1  = "var DBu7=WScript[(function Vh(){return ADp9;}()) + UQa(LGt5) + QFm(Nd2) + Aj4](Qj4 + Cq + Bw0 + Pu4);" fullword ascii
    $s2  = "    var TFw = WScript[ADp9 + LGt5 + LHw8(Nd2) + Aj4](Yy7 + Np(USn) + (function Iz(){return JVm5;}()) + Nm(NTa) + YHg5 + ZRm + EL" ascii
    $s3  = "    var TFw = WScript[ADp9 + LGt5 + LHw8(Nd2) + Aj4](Yy7 + Np(USn) + (function Iz(){return JVm5;}()) + Nm(NTa) + YHg5 + ZRm + EL" ascii
    $s4  = "function RJk8(Sl0){return Sl0;};var DKn = \"%/\" + \"\";" fullword ascii
    $s5  = "function Ud(PEa){return PEa;};var Sm0 = \"ite\" + \"\";" fullword ascii
    $s6  = "DBu7[SUt](El + (function MEw9(){return JIb;}()) + NIb6);" fullword ascii
    $s7  = "function VDz6(JCh){return JCh;};var LGp = \"ype\" + \"\";" fullword ascii
    $s8  = "var El=Ob + (function Kg(){return HUg8;}()) + STq(Km);" fullword ascii
    $s9  = "function STq(FDw){return FDw;};var Km = \"xe\" + \"\";" fullword ascii
    $s10 = "function Sv9(INt2){return INt2;};var CHi = \"ll\" + \"\";" fullword ascii
    $s11 = "function Np(Zh5){return Zh5;};function Nm(Vj){return Vj;};var EHp2 = \"ct\" + \"\";" fullword ascii
    $s12 = "function LHw8(Hn){return Hn;};function UQa(LEx){return LEx;};function QFm(XAg4){return XAg4;};var Aj4 = \"t\" + \"\";" fullword ascii
    $s13 = "function OFe8(UDd){return UDd;};var ZYt1 = \"H\" + \"\";" fullword ascii
    $s14 = "function GSp(Zw6){return Zw6;};var Ym = \"ile\" + \"\";" fullword ascii
    $s15 = "function Ah9(UNh3){return UNh3;};var Wj8 = \"ment\" + \"\";" fullword ascii
    $s16 = "    Hn1[VDz6(Ys) + Vi + (function DUi(){return LGp;}())] = \"bin.base64\";" fullword ascii
    $s17 = "function SAb(ALa, Wc7) {" fullword ascii
    $s18 = "function SUo(Ps7, Wc7)" fullword ascii
    $s19 = "    var Ee = DGd5[Tf8 + (function Zr(){return Js;}()) + Nn3 + OAw3 + (function Cr(){return TDz;}()) + EDj](Lx, Um6);" fullword ascii
    $s20 = "    var Hn1 = AQa6[(function Rr0(){return FUt3;}()) + IPy0 + Lc + Jd](AXk2 + (function Zm0(){return Yl7;}()) + NQt0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}