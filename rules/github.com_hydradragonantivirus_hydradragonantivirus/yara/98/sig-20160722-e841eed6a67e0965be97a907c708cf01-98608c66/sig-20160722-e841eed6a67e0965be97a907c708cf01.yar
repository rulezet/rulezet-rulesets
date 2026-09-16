rule sig_20160722_e841eed6a67e0965be97a907c708cf01 {
  meta:
    description = "datamaliciousorder - file 20160722_e841eed6a67e0965be97a907c708cf01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90c5ccefedf38462224a3c4d359a5dec32bd6c716856d078084c32362d4f9879"

  strings:
    $s1  = "var Ri=WScript[OJb0 + Nc8 + (function RHh(){return JQj;}()) + CIk8](Dm + THr + GUd2(Rw) + NLl + Ka);" fullword ascii
    $s2  = "    var LPn = WScript[OJb0 + Nc8 + JQj + CIk8]((function LLc4(){return VZb;}()) + RNo + Qb);" fullword ascii
    $s3  = "function GUd2(FYw5){return FYw5;};var Ka = \"l\" + \"\";" fullword ascii
    $s4  = "function TLk0(Fp){return Fp;};var Gu1 = \"le\" + \"\";" fullword ascii
    $s5  = "function Xe(ZMh){return ZMh;};var ASs = \"rBu\" + \"\";" fullword ascii
    $s6  = "function Zu(Cf4){return Cf4;};function Nn9(Aw){return Aw;};var Mr0 = \"e\" + \"\";" fullword ascii
    $s7  = "function YTl(WOv){return WOv;};var Xn7 = \"e\" + \"\";" fullword ascii
    $s8  = "function RHy(Vm){return Vm;};var ZMh9 = \"t\" + \"\";" fullword ascii
    $s9  = "function JPk9(RTw1){return RTw1;};var CIk8 = \"ect\" + \"\";" fullword ascii
    $s10 = "function ZPq2(XBs){return XBs;};var CKw = \"P%/\" + \"\";" fullword ascii
    $s11 = "function DLv(QAm, Xu) {" fullword ascii
    $s12 = "function TWi3(Ir, Xu)" fullword ascii
    $s13 = "   Xf = new ActiveXObject(QMn + Cm + XKc2 + OGl1 + FQl + (function MCw(){return RGt;}()) + Ed)" fullword ascii
    $s14 = "   Lo = Xf[(function Wy(){return KYh0;}()) + EXb2 + Bv + (function PMf(){return FUj;}())](Xu, IWv9, true)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}