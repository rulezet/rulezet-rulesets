rule TTP_XOR_QUAD_CurrentVersionRun_31b5 {
  strings:
    $key_31b5 = { 62 da [2] 46 d4 [2] 6d f8 [2] 43 da [2] 57 c1 [2] 58 db [2] 46 c6 [2] 44 c7 [2] 5f c1 [2] 43 c6 [2] 5f e9 }

  condition:
    any of them
}