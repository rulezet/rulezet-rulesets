rule TTP_XOR_QUAD_CurrentVersionRun_13d4 {
  strings:
    $key_13d4 = { 40 bb [2] 64 b5 [2] 4f 99 [2] 61 bb [2] 75 a0 [2] 7a ba [2] 64 a7 [2] 66 a6 [2] 7d a0 [2] 61 a7 [2] 7d 88 }

  condition:
    any of them
}