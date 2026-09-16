rule sig_20160414_f6b13b2ca86a053160c2829bf219b613 {
  meta:
    description = "datamaliciousorder - file 20160414_f6b13b2ca86a053160c2829bf219b613.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "998fa99201c8b53a3c29746ad34402704eaa07b3c6a7d78d7d2ffce4890e0562"

  strings:
    $s1  = "while (hTC < Ylt - (1873, 4643, 7554, 662, 6667, 3139, 5812, 4384, 2)) {" fullword ascii
    $s2  = "return PgsJ + mPKa;" fullword ascii
    $s3  = "var HTmPLX = true;" fullword ascii
    $s4  = "switch (\"1\") {" fullword ascii
    $s5  = "var hMoJZ = true;" fullword ascii
    $s6  = "var OlIAM = false;" fullword ascii
    $s7  = "var PIeEmTB = false;" fullword ascii
    $s8  = "var TwxqeB = false;" fullword ascii
    $s9  = "switch (\"0\") {" fullword ascii
    $s10 = "if (BMloBro === true) {" fullword ascii
    $s11 = "if (uIkt == true) {" fullword ascii
    $s12 = "switch (ytZ) {" fullword ascii
    $s13 = "var etyNSEo = true;" fullword ascii
    $s14 = "if (Fyj == true) {" fullword ascii
    $s15 = "function kJFZ() {" fullword ascii
    $s16 = "var gcKZKc = true;" fullword ascii
    $s17 = "function DqvyPy(yey, gTk) {" fullword ascii
    $s18 = "var otZP = false;" fullword ascii
    $s19 = "return MMrR;" fullword ascii
    $s20 = "var YjmNY = true;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}