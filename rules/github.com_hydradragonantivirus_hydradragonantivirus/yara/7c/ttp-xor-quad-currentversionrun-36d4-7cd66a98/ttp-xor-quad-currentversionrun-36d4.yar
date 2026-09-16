rule TTP_XOR_QUAD_CurrentVersionRun_36d4 {
  strings:
    $key_36d4 = { 65 bb [2] 41 b5 [2] 6a 99 [2] 44 bb [2] 50 a0 [2] 5f ba [2] 41 a7 [2] 43 a6 [2] 58 a0 [2] 44 a7 [2] 58 88 }

  condition:
    any of them
}