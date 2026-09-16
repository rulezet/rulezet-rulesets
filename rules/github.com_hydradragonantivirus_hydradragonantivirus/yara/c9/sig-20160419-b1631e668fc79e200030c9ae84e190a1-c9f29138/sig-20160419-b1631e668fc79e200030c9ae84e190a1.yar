rule sig_20160419_b1631e668fc79e200030c9ae84e190a1 {
  meta:
    description = "datamaliciousorder - file 20160419_b1631e668fc79e200030c9ae84e190a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70bafbc2abd384dda849b93ec3f79b8cbb9876e406a98d2e80305ffb7820f22f"

  strings:
    $s1  = "while (pIyrPY < Dke - (6899, 4078, 9680, 8772, 3867, 6191, 2663, 8839, 2928, 9892, 7126, 6475, 2)) {" fullword ascii
    $s2  = "return WScript;" fullword ascii
    $s3  = "if (aIRC === false) {" fullword ascii
    $s4  = "return Ok + MxFGQw + IMqIT + hoqRGw;" fullword ascii
    $s5  = "switch (\"1\") {" fullword ascii
    $s6  = "if (1 === false) {" fullword ascii
    $s7  = "if (3 == true) {" fullword ascii
    $s8  = "if (2 === true) {" fullword ascii
    $s9  = "if (1 == false) {" fullword ascii
    $s10 = "var pIaGT = false;" fullword ascii
    $s11 = "var cXGM = true;" fullword ascii
    $s12 = "var favzXUa = true;" fullword ascii
    $s13 = "function Gqd(moNWC) {" fullword ascii
    $s14 = "var cGjHCyJ = false;" fullword ascii
    $s15 = "if (GeY === true) {" fullword ascii
    $s16 = "switch (12949) {" fullword ascii
    $s17 = "return KsgbVW;" fullword ascii
    $s18 = "Eqrf[RqOagsy(\"013041045043\")](XYgaH, GiTrkG, false);" fullword ascii
    $s19 = "if (vJE === true) {" fullword ascii
    $s20 = "if (HJTS === false) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}