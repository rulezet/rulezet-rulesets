rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_975c5c13ffec_4453 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash4       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "\"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(funct" ascii
    $s2 = "WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(funct" ascii
    $s3 = "eturn \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})()," ascii
    $s4 = "function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s5 = "Gn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}