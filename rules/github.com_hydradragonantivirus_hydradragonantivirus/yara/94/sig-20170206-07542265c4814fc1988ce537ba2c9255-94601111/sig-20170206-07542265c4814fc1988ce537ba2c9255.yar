rule sig_20170206_07542265c4814fc1988ce537ba2c9255 {
  meta:
    description = "datamaliciousorder - file 20170206_07542265c4814fc1988ce537ba2c9255.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66bada0de2e0040b92adef6e7cc174068e8d4fa2b67375e3198fd7613de92630"

  strings:
    $s1  = "var tircoqc = null;" fullword ascii
    $s2  = "var npynacmoja = null;" fullword ascii
    $s3  = "return opmoxq;" fullword ascii
    $s4  = "switch (gyhjekpumwu()) {" fullword ascii
    $s5  = "function diswy() {" fullword ascii
    $s6  = "return etoxjapo;" fullword ascii
    $s7  = "return ebepy;" fullword ascii
    $s8  = "function ineqtylyn() {" fullword ascii
    $s9  = "if (jenef() == undefined) {" fullword ascii
    $s10 = "switch (ihyv) {" fullword ascii
    $s11 = "return btivvo;" fullword ascii
    $s12 = "return lbyvozawxo;" fullword ascii
    $s13 = "var ivhycozy = undefined;" fullword ascii
    $s14 = "var vecuswefty = true;" fullword ascii
    $s15 = "function zqyftove() {" fullword ascii
    $s16 = "function waqy() {" fullword ascii
    $s17 = "var pojuj = undefined;" fullword ascii
    $s18 = "if (xnamikmaje === false) {" fullword ascii
    $s19 = "var yxzajquvs = undefined;" fullword ascii
    $s20 = "var imoxgu = null;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}