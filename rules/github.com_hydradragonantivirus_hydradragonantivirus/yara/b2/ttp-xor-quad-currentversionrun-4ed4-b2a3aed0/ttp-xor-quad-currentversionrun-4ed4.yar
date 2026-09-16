rule TTP_XOR_QUAD_CurrentVersionRun_4ed4 {
  strings:
    $key_4ed4 = { 1d bb [2] 39 b5 [2] 12 99 [2] 3c bb [2] 28 a0 [2] 27 ba [2] 39 a7 [2] 3b a6 [2] 20 a0 [2] 3c a7 [2] 20 88 }

  condition:
    any of them
}