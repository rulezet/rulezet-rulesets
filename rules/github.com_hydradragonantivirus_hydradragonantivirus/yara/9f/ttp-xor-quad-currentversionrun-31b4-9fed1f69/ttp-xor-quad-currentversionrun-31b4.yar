rule TTP_XOR_QUAD_CurrentVersionRun_31b4 {
  strings:
    $key_31b4 = { 62 db [2] 46 d5 [2] 6d f9 [2] 43 db [2] 57 c0 [2] 58 da [2] 46 c7 [2] 44 c6 [2] 5f c0 [2] 43 c7 [2] 5f e8 }

  condition:
    any of them
}