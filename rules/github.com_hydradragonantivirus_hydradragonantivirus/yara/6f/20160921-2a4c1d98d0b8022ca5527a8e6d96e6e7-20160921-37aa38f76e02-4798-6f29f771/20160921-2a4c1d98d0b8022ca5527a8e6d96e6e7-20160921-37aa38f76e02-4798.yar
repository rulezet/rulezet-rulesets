rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_37aa38f76e02_4798 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_37aa38f76e02afb64903280105ce4597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"

  strings:
    $s1 = " \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s2 = "on f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s3 = "),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){" ascii
    $s4 = "n \"Nx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(func" ascii
    $s5 = "\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}