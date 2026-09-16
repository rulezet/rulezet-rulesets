rule TTP_XOR_QUAD_CurrentVersionRun_4fd4 {
  strings:
    $key_4fd4 = { 1c bb [2] 38 b5 [2] 13 99 [2] 3d bb [2] 29 a0 [2] 26 ba [2] 38 a7 [2] 3a a6 [2] 21 a0 [2] 3d a7 [2] 21 88 }

  condition:
    any of them
}