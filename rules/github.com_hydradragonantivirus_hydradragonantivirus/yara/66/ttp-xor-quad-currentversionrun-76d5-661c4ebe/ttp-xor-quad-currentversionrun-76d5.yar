rule TTP_XOR_QUAD_CurrentVersionRun_76d5 {
  strings:
    $key_76d5 = { 25 ba [2] 01 b4 [2] 2a 98 [2] 04 ba [2] 10 a1 [2] 1f bb [2] 01 a6 [2] 03 a7 [2] 18 a1 [2] 04 a6 [2] 18 89 }

  condition:
    any of them
}