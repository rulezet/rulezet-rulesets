rule TTP_XOR_QUAD_CurrentVersionRun_2cba {
  strings:
    $key_2cba = { 7f d5 [2] 5b db [2] 70 f7 [2] 5e d5 [2] 4a ce [2] 45 d4 [2] 5b c9 [2] 59 c8 [2] 42 ce [2] 5e c9 [2] 42 e6 }

  condition:
    any of them
}