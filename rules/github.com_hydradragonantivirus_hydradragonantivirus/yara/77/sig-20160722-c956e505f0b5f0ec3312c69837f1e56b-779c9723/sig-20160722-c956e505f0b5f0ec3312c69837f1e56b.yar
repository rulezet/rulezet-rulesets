rule sig_20160722_c956e505f0b5f0ec3312c69837f1e56b {
  meta:
    description = "datamaliciousorder - file 20160722_c956e505f0b5f0ec3312c69837f1e56b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3534b049dcf2162514c19358c7e0b2a82f7a29c96cba135e0fd0c9a6c5aeaa47"

  strings:
    $s1  = "var TCe=WScript[RMc2 + Ph + (function Qb1(){return Gx;}()) + TRb](Up7 + Lg(Dy4) + QHb(YEy7));" fullword ascii
    $s2  = "function Lg(Px){return Px;};function QHb(Qu){return Qu;};var YEy7 = \"Shell\" + \"\";" fullword ascii
    $s3  = "    var THz = WScript[RMc2 + Ph + (function Rc0(){return Gx;}()) + TRb](Er + Ss + CFi + LVz2 + EZx(BHg) + FZv0 + (function JJt8(" ascii
    $s4  = "    var Gz1 = WScript[RMc2 + Ph + Gx + TRb](Jn1(DZy) + AEd + TAm + Cg0(Nr) + FHw(Hs) + GKd + (function Od4(){return Pu;}()));" fullword ascii
    $s5  = "    var THz = WScript[RMc2 + Ph + (function Rc0(){return Gx;}()) + TRb](Er + Ss + CFi + LVz2 + EZx(BHg) + FZv0 + (function JJt8(" ascii
    $s6  = "function RWa9(YCd){return YCd;};var Sf2 = \"ile\" + \"\";" fullword ascii
    $s7  = "function Oo5(PUi0){return PUi0;};var NEz = \"e\" + \"\";" fullword ascii
    $s8  = "function Mc7(Hm){return Hm;};var Uq = \"a\" + \"\";" fullword ascii
    $s9  = "function YJg(SCg0){return SCg0;};var Wi = \"tream\" + \"\";" fullword ascii
    $s10 = "var VKb=LZl3 + (function Fl(){return Fb;}()) + (function UHr8(){return NXn9;}()) + WDk + Lr + Yi0;" fullword ascii
    $s11 = "function IYz7(KJw){return KJw;};var Bk = \"ment\" + \"\";" fullword ascii
    $s12 = "function EZx(BAj9){return BAj9;};var BKo = \"t\" + \"\";" fullword ascii
    $s13 = "function Jn1(QYo){return QYo;};function Cg0(Uc8){return Uc8;};function FHw(Ny){return Ny;};var Pu = \"t\" + \"\";" fullword ascii
    $s14 = "return NFp5;}()) + Pr);" fullword ascii
    $s15 = "    RLt[Uv + (function JDo0(){return Kx;}()) + Ak] = \"bin.base64\";" fullword ascii
    $s16 = "    var Xb5 = WScript[(function VEg9(){return RMc2;}()) + Ph + Gx + (function Pn(){return TRb;}())](RHc + LCa + (function GKf(){" ascii
    $s17 = "    var Xb5 = WScript[(function VEg9(){return RMc2;}()) + Ph + Gx + (function Pn(){return TRb;}())](RHc + LCa + (function GKf(){" ascii
    $s18 = "){return BKo;}()));" fullword ascii
    $s19 = "function IYv9(Bu6, Nw) {" fullword ascii
    $s20 = "function Uw(KRt6, Nw)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}