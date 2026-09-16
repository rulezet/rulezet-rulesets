rule sig_20161002_1fa0e47d8d960714c4507f61ebf95e9e {
  meta:
    description = "datamaliciousorder - file 20161002_1fa0e47d8d960714c4507f61ebf95e9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14e5a7d09349110699a75fdad55705d0dbc1d897c362ac78ac3e37df25b0f4e4"

  strings:
    $x1  = "usakuk.run(\"cmd.EXe /c POWers^H^ell.^E^x^E  -E^X^ecu^Ti^OnP^OL^ICY^    ^byp^Ass^   -noprO^fi^lE -^wI^N^dOWsty^l^E h^iddE^n  (NE" ascii
    $s2  = "pDAta%.EXe'\", false);" fullword ascii
    $s3  = "return 'ofile.dou';" fullword ascii
    $s4  = "switch (ucdovmo) {" fullword ascii
    $s5  = "return avibopl;" fullword ascii
    $s6  = "function oxiglaqu() {" fullword ascii
    $s7  = "var mwoxolyhr = typeof null;" fullword ascii
    $s8  = "var ucdovmo = undefined;" fullword ascii
    $s9  = "function nywogixm() {" fullword ascii
    $s10 = "var kofid = typeof null;" fullword ascii
    $s11 = "function eqicvo() {" fullword ascii
    $s12 = "return 'xun4';" fullword ascii
    $s13 = "var zylfuqt = typeof true;" fullword ascii
    $s14 = "function frihnebno() {" fullword ascii
    $s15 = "var ojudbo = undefined;" fullword ascii
    $s16 = "var ygamekbe = typeof null;" fullword ascii
    $s17 = "var wozmebk = typeof undefined;" fullword ascii
    $s18 = "var iguhzerka = null;" fullword ascii
    $s19 = "if (zhyhekji() === undefined) {" fullword ascii
    $s20 = "var wynuc = undefined;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}