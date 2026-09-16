rule sig_20160722_8bf2ea010c661d7bdbd9579587d6de88 {
  meta:
    description = "datamaliciousorder - file 20160722_8bf2ea010c661d7bdbd9579587d6de88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ca4ad3001945103e76d4b785bb90301d4966e5137be35b4126f8ee433ffe55c"

  strings:
    $s1  = "var Ee9=WScript[Fn8 + Mc3 + Wq0 + HNd9 + NBs](Nv + PRi4 + XHk9(Qf) + YTu + (function BSk(){return Vj;}()) + Ip);" fullword ascii
    $s2  = "function Rl0(HWw4){return HWw4;};var LQb = \"Run\" + \"\";" fullword ascii
    $s3  = "    var Xa1 = WScript[Fn8 + Mc3 + Wq0 + HNd9 + Ub1(NBs)](COc(In4) + OKm1 + Ap + (function JOh(){return Yx9;}()) + DQx(DAb) + Im1" ascii
    $s4  = "    var Xa1 = WScript[Fn8 + Mc3 + Wq0 + HNd9 + Ub1(NBs)](COc(In4) + OKm1 + Ap + (function JOh(){return Yx9;}()) + DQx(DAb) + Im1" ascii
    $s5  = "    var Xe2 = WScript[(function Va(){return Fn8;}()) + Mc3 + WEw(Wq0) + HNd9 + (function IKo(){return NBs;}())](FFc8 + (function" ascii
    $s6  = "    var Xe2 = WScript[(function Va(){return Fn8;}()) + Mc3 + WEw(Wq0) + HNd9 + (function IKo(){return NBs;}())](FFc8 + (function" ascii
    $s7  = "function LWi9(SOz){return SOz;};function WYj(QTr){return QTr;};var VFr = \"e\" + \"\";" fullword ascii
    $s8  = "function XHk9(He1){return He1;};var Ip = \"ll\" + \"\";" fullword ascii
    $s9  = "function Ks(QFm2){return QFm2;};var IWf = \"ata\" + \"\";" fullword ascii
    $s10 = ";function YMr0(AQw7){return AQw7;};function DYe(Za9){return Za9;};var HVo = \"t\" + \"\";" fullword ascii
    $s11 = " Le(){return Zl2;}()) + (function Az(){return Kx4;}()) + VEl8(RJe1) + Il1);" fullword ascii
    $s12 = "function EZo(He){return He;};var Vd5 = \"eam\" + \"\";" fullword ascii
    $s13 = "function Pi2(IQg){return IQg;};var DYb6 = \"t\" + \"\";" fullword ascii
    $s14 = "function COc(HGr){return HGr;};function DQx(PRj9){return PRj9;};function Nx(OOw9){return OOw9;};function Rc8(QGl2){return QGl2;}" ascii
    $s15 = "var Ul7=Jj4 + Uw + (function XDw(){return ZOa0;}());" fullword ascii
    $s16 = "function Fs2(Vq){return Vq;};function VTj(THw1){return THw1;};var LVj5 = \"eam\" + \"\";" fullword ascii
    $s17 = "function Hy(Jz7){return Jz7;};var KSz = \"le\" + \"\";" fullword ascii
    $s18 = "function Ub1(BEf8){return BEf8;};function WEw(Cw){return Cw;};var NBs = \"t\" + \"\";" fullword ascii
    $s19 = "function VEl8(JYz0){return JYz0;};var Il1 = \"ent\" + \"\";" fullword ascii
    $s20 = "function LRb4(RDf7){return RDf7;};var ZNb3 = \"te\" + \"\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}