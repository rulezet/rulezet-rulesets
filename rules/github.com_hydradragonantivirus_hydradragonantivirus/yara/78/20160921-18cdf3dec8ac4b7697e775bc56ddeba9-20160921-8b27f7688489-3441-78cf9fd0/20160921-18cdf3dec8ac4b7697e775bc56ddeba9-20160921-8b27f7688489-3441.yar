rule _20160921_18cdf3dec8ac4b7697e775bc56ddeba9_20160921_8b27f7688489_3441 {
  meta:
    description = "datamaliciousorder - from files 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "rn \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(fu" ascii
    $s2 = "nction f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s3 = "\"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";" ascii
    $s5 = "nction f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){retur" ascii
    $s6 = "unction f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}