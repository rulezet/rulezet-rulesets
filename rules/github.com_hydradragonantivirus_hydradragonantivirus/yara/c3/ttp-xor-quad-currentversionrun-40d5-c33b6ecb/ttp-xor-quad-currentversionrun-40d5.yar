rule TTP_XOR_QUAD_CurrentVersionRun_40d5 {
  strings:
    $key_40d5 = { 13 ba [2] 37 b4 [2] 1c 98 [2] 32 ba [2] 26 a1 [2] 29 bb [2] 37 a6 [2] 35 a7 [2] 2e a1 [2] 32 a6 [2] 2e 89 }

  condition:
    any of them
}