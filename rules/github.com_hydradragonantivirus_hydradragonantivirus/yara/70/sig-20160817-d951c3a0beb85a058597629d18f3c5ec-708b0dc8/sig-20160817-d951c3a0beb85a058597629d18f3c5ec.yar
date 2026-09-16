rule sig_20160817_d951c3a0beb85a058597629d18f3c5ec {
  meta:
    description = "datamaliciousorder - file 20160817_d951c3a0beb85a058597629d18f3c5ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af6a81a6b123bff985f36a52de0aa6a8f754d16f06c84afc0b168c0fff4260cb"

  strings:
    $s1  = "var cytihuz = [\"55665\", \"famofma\", \"43217\", \"28467\", fpynifn0[1] + zihygced0[4] + oqelxuvty5[0] + zbyxyrje2[1] + kudu[5]" ascii
    $s2  = "var cytihuz = [\"55665\", \"famofma\", \"43217\", \"28467\", fpynifn0[1] + zihygced0[4] + oqelxuvty5[0] + zbyxyrje2[1] + kudu[5]" ascii
    $s3  = "return tyqbinzomw[1];" fullword ascii
    $s4  = "function puxpeph0() {" fullword ascii
    $s5  = "function urkuvydpi6() {" fullword ascii
    $s6  = "return zaxcu8[\"ezxykky\"];" fullword ascii
    $s7  = "return ytmohfef1[1];" fullword ascii
    $s8  = "return sokypyv0[\"isbypi\"];" fullword ascii
    $s9  = "function waza() {" fullword ascii
    $s10 = "function eczoduc() {" fullword ascii
    $s11 = "return ecux[\"ulsoc\"];" fullword ascii
    $s12 = "function walhomwyw() {" fullword ascii
    $s13 = "function azbor7() {" fullword ascii
    $s14 = "function tjyluxe9() {" fullword ascii
    $s15 = "return umibacm5[\"muto\"];" fullword ascii
    $s16 = "function huhuwry5() {" fullword ascii
    $s17 = "function vzorubex() {" fullword ascii
    $s18 = "function axsesivp9() {" fullword ascii
    $s19 = "return tkolydy6[\"xkyrkuc\"];" fullword ascii
    $s20 = "function razelgat8() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}