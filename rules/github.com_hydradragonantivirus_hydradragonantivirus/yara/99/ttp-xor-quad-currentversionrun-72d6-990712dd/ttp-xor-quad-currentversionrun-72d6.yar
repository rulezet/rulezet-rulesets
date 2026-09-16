rule TTP_XOR_QUAD_CurrentVersionRun_72d6 {
  strings:
    $key_72d6 = { 21 b9 [2] 05 b7 [2] 2e 9b [2] 00 b9 [2] 14 a2 [2] 1b b8 [2] 05 a5 [2] 07 a4 [2] 1c a2 [2] 00 a5 [2] 1c 8a }

  condition:
    any of them
}