rule TTP_XOR_QUAD_CurrentVersionRun_5ab5 {
  strings:
    $key_5ab5 = { 09 da [2] 2d d4 [2] 06 f8 [2] 28 da [2] 3c c1 [2] 33 db [2] 2d c6 [2] 2f c7 [2] 34 c1 [2] 28 c6 [2] 34 e9 }

  condition:
    any of them
}