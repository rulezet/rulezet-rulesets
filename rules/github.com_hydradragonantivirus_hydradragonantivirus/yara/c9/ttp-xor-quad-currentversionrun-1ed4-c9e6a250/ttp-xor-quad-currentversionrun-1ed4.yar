rule TTP_XOR_QUAD_CurrentVersionRun_1ed4 {
  strings:
    $key_1ed4 = { 4d bb [2] 69 b5 [2] 42 99 [2] 6c bb [2] 78 a0 [2] 77 ba [2] 69 a7 [2] 6b a6 [2] 70 a0 [2] 6c a7 [2] 70 88 }

  condition:
    any of them
}