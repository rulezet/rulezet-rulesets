rule _20160921_90c3374aed1b4618a92eb40cb007c4b4_20160921_994c4aa88136_5537 {
  meta:
    description = "datamaliciousorder - from files 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash4       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "00(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\"" ascii
    $s2 = "KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s3 = "n \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(fun" ascii
    $s4 = "KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(functio" ascii
    $s5 = " f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}