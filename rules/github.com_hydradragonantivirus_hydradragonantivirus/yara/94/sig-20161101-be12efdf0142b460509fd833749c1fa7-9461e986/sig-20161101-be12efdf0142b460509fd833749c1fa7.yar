rule sig_20161101_be12efdf0142b460509fd833749c1fa7 {
  meta:
    description = "datamaliciousorder - file 20161101_be12efdf0142b460509fd833749c1fa7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c75991740fe48d3b71c477eabd3251c3004cac12a980984c9d3db22fe7a3af1c"

  strings:
    $s1  = "function snyplograjfu() {" fullword ascii
    $s2  = "return ircoji;" fullword ascii
    $s3  = "return giqjuf;" fullword ascii
    $s4  = "function atqeje() {" fullword ascii
    $s5  = "var edahne = typeof undefined;" fullword ascii
    $s6  = "if (ecnivzevugz() == null) {" fullword ascii
    $s7  = "var ihajhi = null;" fullword ascii
    $s8  = "function ehyru() {" fullword ascii
    $s9  = "var oluvsote = null;" fullword ascii
    $s10 = "function elvepd() {" fullword ascii
    $s11 = "return yrnowatl;" fullword ascii
    $s12 = "var efyjlehzypf = true;" fullword ascii
    $s13 = "return yryrons;" fullword ascii
    $s14 = "function ymytdorc() {" fullword ascii
    $s15 = "var cvexpiga = undefined;" fullword ascii
    $s16 = "var byfyno = null;" fullword ascii
    $s17 = "function ewavwo() {" fullword ascii
    $s18 = "var okugap = undefined;" fullword ascii
    $s19 = "function oqaknebbu() {" fullword ascii
    $s20 = "return fmyllak;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}