rule TTP_XOR_QUAD_CurrentVersionRun_51d5 {
  strings:
    $key_51d5 = { 02 ba [2] 26 b4 [2] 0d 98 [2] 23 ba [2] 37 a1 [2] 38 bb [2] 26 a6 [2] 24 a7 [2] 3f a1 [2] 23 a6 [2] 3f 89 }

  condition:
    any of them
}