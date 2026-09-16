rule TTP_XOR_QUAD_CurrentVersionRun_02d4 {
  strings:
    $key_02d4 = { 51 bb [2] 75 b5 [2] 5e 99 [2] 70 bb [2] 64 a0 [2] 6b ba [2] 75 a7 [2] 77 a6 [2] 6c a0 [2] 70 a7 [2] 6c 88 }

  condition:
    any of them
}