rule sig_20160722_c1eefae92b65a3113e89140e21d732d8 {
  meta:
    description = "datamaliciousorder - file 20160722_c1eefae92b65a3113e89140e21d732d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f1203516dd36345cf22a2ed9cec844e960528c0f6e278b501e2f0d335d0cc36"

  strings:
    $s1  = "    var JCm4 = WScript[(function Js0(){return AMb;}()) + Ij2 + Pq + MUj2 + Jl](St + AFp + Sa + TAz3 + GLg + Wq2 + WRd6);" fullword ascii
    $s2  = "    var Ec = WScript[AMb + Ij2 + (function FCm2(){return Pq;}()) + MUj2 + (function FBe(){return Jl;}())](Xo3 + JGf1 + Pn5 + LYc" ascii
    $s3  = "    var Ec = WScript[AMb + Ij2 + (function FCm2(){return Pq;}()) + MUj2 + (function FBe(){return Jl;}())](Xo3 + JGf1 + Pn5 + LYc" ascii
    $s4  = "Rp[(function XYi9(){return Io;}())](Uq7 + CZg4);" fullword ascii
    $s5  = "function Za(Kv){return Kv;};var LPh = \"te\" + \"\";" fullword ascii
    $s6  = "var Ri=SVg3 + KCm + EEg0 + (function XIe(){return Av;}());" fullword ascii
    $s7  = "function Ya6(Ik9){return Ik9;};function Jq(Hk4){return Hk4;};var UPo5 = \"e\" + \"\";" fullword ascii
    $s8  = "function CPb(REi){return REi;};var AFd = \"%/\" + \"\";" fullword ascii
    $s9  = "function MTz(AMx){return AMx;};var FBj = \"File\" + \"\";" fullword ascii
    $s10 = "function Ey0(Ll4){return Ll4;};var Jl = \"t\" + \"\";" fullword ascii
    $s11 = "function SDc(Vg6){return Vg6;};var Dn8 = \".e\" + \"\";" fullword ascii
    $s12 = "function Zu(VAf0){return VAf0;};function Ed0(DVr){return DVr;};var TBn = \"ement\" + \"\";" fullword ascii
    $s13 = "function Lc(Qb){return Qb;};function Ch6(Lw1){return Lw1;};function Wl(CXg4){return CXg4;};var WRd6 = \"ct\" + \"\";" fullword ascii
    $s14 = "function ICa(THr0){return THr0;};var Dj = \"in\" + \"\";" fullword ascii
    $s15 = "function Tw3(Zq2, Wx4)" fullword ascii
    $s16 = "function Kz0(Hm5, Wx4) {" fullword ascii
    $s17 = "function Sn(CAh7){return CAh7;};var Bm = \"File\" + \"\";" fullword ascii
    $s18 = "    Uv[MFw + LPh](LQw7[Sa0 + Hg + (function AKx8(){return FBf;}()) + Jl0]);" fullword ascii
    $s19 = "    var LQw7 = Ec[Zu(Rj) + Ed0(Mh5) + (function Rz6(){return TBn;}())](Bz + MNw + Ni1);" fullword ascii
    $s20 = "    LQw7[(function Dg(){return Me;}()) + Jn] = VRd[Al5 + Km + Mf]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}