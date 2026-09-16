rule sig_20170427_661f88e902e0c22a88ef8c53517193ec {
  meta:
    description = "datamaliciousorder - file 20170427_661f88e902e0c22a88ef8c53517193ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d9f07303307300fa69a36b221699dae36f798435597af28ebabb36d5440bf9c"

  strings:
    $s1 = "return gjlyFCpsAORKXUGhLe.split(LMyQkogEupxIXDTR).join(\"\"); }" fullword ascii
    $s2 = "if (FQGRNaLqikoBUvTsD() == false) {" fullword ascii
    $s3 = "function XOyVnRvEqrjMwfcFaAT(gjlyFCpsAORKXUGhLe, LMyQkogEupxIXDTR) { " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}