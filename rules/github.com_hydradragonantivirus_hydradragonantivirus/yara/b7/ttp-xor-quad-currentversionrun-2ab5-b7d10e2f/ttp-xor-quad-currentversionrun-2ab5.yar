rule TTP_XOR_QUAD_CurrentVersionRun_2ab5 {
  strings:
    $key_2ab5 = { 79 da [2] 5d d4 [2] 76 f8 [2] 58 da [2] 4c c1 [2] 43 db [2] 5d c6 [2] 5f c7 [2] 44 c1 [2] 58 c6 [2] 44 e9 }

  condition:
    any of them
}