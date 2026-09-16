rule sig_20160722_89875797048f4e92bc2a45eb0bc20c63 {
  meta:
    description = "datamaliciousorder - file 20160722_89875797048f4e92bc2a45eb0bc20c63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b85704ece478d5e48b147a680b9afd617b2fb044c91eb940e7a9eb5ddf05ac16"

  strings:
    $s1  = "var PKp=WScript[ZBv7(FOi5) + Uu4 + Ab + Wl6(ADe1)]((function Ze2(){return AJk0;}()) + WLv + Gy7 + Cv);" fullword ascii
    $s2  = "    var RAh1 = WScript[FOi5 + Uu4 + Ab + ADe1](YNd0 + QKl + DVn3 + ZOe + (function HNk8(){return Uv2;}()) + CWo + Pd + ANb);" fullword ascii
    $s3  = "    var AHp6 = WScript[FOi5 + Uu4 + Ab + ADe1](Uw3(Ej) + (function YNq(){return BYu;}()) + ZWu(Dq5) + Br + Qo(Ge));" fullword ascii
    $s4  = "function WLo0(FXd){return FXd;};var DMm9 = \"l\" + \"\";" fullword ascii
    $s5  = "function LPw(FQs){return FQs;};var Lk9 = \"xe\" + \"\";" fullword ascii
    $s6  = "function Gd3(Rh){return Rh;};var Zw = \"e\" + \"\";" fullword ascii
    $s7  = "function Mj(Vn1){return Vn1;};var JDj4 = \"4Data\" + \"\";" fullword ascii
    $s8  = "function SYm(Vm5){return Vm5;};var JXk1 = \"MP%/\" + \"\";" fullword ascii
    $s9  = "n Lf5(){return CWo;}()) + YTc(Pd) + ANb)" fullword ascii
    $s10 = "function Uw3(WAo0){return WAo0;};function ZWu(Ks0){return Ks0;};function Qo(VDb0){return VDb0;};var Ge = \"am\" + \"\";" fullword ascii
    $s11 = "function TMn3(JEb){return JEb;};var CRj = \".b\" + \"\";" fullword ascii
    $s12 = "function AOv(BTx){return BTx;};var NCj = \"ile\" + \"\";" fullword ascii
    $s13 = "function ZBv7(Uk){return Uk;};function Wl6(MEj6){return MEj6;};var ADe1 = \"ect\" + \"\";" fullword ascii
    $s14 = "function OCn0(WIr9){return WIr9;};function YTc(Nw){return Nw;};var ANb = \"t\" + \"\";" fullword ascii
    $s15 = "function IFb0(UCk){return UCk;};var Wx3 = \"0KT\" + \"\";" fullword ascii
    $s16 = "function Lo3(Bd){return Bd;};function Yb0(Td6){return Td6;};function EVo2(Lr){return Lr;};var Wa1 = \"ent\" + \"\";" fullword ascii
    $s17 = "function QZs(Of, VJi)" fullword ascii
    $s18 = "function JTs(JVy7, VJi) {" fullword ascii
    $s19 = "    AHp6[(function ABc4(){return Ba7;}()) + GQg](Ev6[SVk + WSi + Ec + (function Yn9(){return Bl3;}()) + (function QOd(){return U" ascii
    $s20 = "   Ao7 = new ActiveXObject(YNd0 + (function Mz0(){return QKl;}()) + (function Hv(){return DVn3;}()) + ZOe + OCn0(Uv2) + (functio" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}