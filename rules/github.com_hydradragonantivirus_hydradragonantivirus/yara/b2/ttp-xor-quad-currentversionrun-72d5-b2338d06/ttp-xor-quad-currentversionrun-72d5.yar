rule TTP_XOR_QUAD_CurrentVersionRun_72d5 {
  strings:
    $key_72d5 = { 21 ba [2] 05 b4 [2] 2e 98 [2] 00 ba [2] 14 a1 [2] 1b bb [2] 05 a6 [2] 07 a7 [2] 1c a1 [2] 00 a6 [2] 1c 89 }

  condition:
    any of them
}