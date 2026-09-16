rule _20160921_202394e6610dfa0f27f737c781d5c579_20160921_6b34f0b83cb5_402 {
  meta:
    description = "datamaliciousorder - from files 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash2       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash3       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash4       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"

  strings:
    $s1  = "on f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s2  = "f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt" ascii
    $s3  = "ction f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s4  = " f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Q" ascii
    $s5  = "turn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})()," ascii
    $s6  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s7  = "0(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";}" ascii
    $s8  = "ction f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s9  = "n f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s10 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f0" ascii
    $s11 = "0(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\"" ascii
    $s12 = " \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s13 = "Xg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s14 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s15 = "t\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s16 = "rn \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"SGs\";})(),(fu" ascii
    $s17 = "(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){re" ascii
    $s18 = "n \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s19 = "u\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function" ascii
    $s20 = "(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}