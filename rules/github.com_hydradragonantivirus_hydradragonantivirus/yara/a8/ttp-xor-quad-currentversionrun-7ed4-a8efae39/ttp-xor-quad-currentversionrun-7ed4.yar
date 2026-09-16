rule TTP_XOR_QUAD_CurrentVersionRun_7ed4 {
  strings:
    $key_7ed4 = { 2d bb [2] 09 b5 [2] 22 99 [2] 0c bb [2] 18 a0 [2] 17 ba [2] 09 a7 [2] 0b a6 [2] 10 a0 [2] 0c a7 [2] 10 88 }

  condition:
    any of them
}