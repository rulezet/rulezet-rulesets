rule TTP_XOR_QUAD_CurrentVersionRun_41b5 {
  strings:
    $key_41b5 = { 12 da [2] 36 d4 [2] 1d f8 [2] 33 da [2] 27 c1 [2] 28 db [2] 36 c6 [2] 34 c7 [2] 2f c1 [2] 33 c6 [2] 2f e9 }

  condition:
    any of them
}