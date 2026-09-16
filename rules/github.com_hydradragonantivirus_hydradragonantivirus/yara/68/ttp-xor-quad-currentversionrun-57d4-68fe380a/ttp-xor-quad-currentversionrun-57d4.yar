rule TTP_XOR_QUAD_CurrentVersionRun_57d4 {
  strings:
    $key_57d4 = { 04 bb [2] 20 b5 [2] 0b 99 [2] 25 bb [2] 31 a0 [2] 3e ba [2] 20 a7 [2] 22 a6 [2] 39 a0 [2] 25 a7 [2] 39 88 }

  condition:
    any of them
}