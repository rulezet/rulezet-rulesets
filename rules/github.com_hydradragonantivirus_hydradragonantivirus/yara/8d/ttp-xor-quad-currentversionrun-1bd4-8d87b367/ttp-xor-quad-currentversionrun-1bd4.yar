rule TTP_XOR_QUAD_CurrentVersionRun_1bd4 {
  strings:
    $key_1bd4 = { 48 bb [2] 6c b5 [2] 47 99 [2] 69 bb [2] 7d a0 [2] 72 ba [2] 6c a7 [2] 6e a6 [2] 75 a0 [2] 69 a7 [2] 75 88 }

  condition:
    any of them
}