rule TTP_XOR_QUAD_CurrentVersionRun_51d4 {
  strings:
    $key_51d4 = { 02 bb [2] 26 b5 [2] 0d 99 [2] 23 bb [2] 37 a0 [2] 38 ba [2] 26 a7 [2] 24 a6 [2] 3f a0 [2] 23 a7 [2] 3f 88 }

  condition:
    any of them
}