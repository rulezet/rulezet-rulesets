rule TTP_XOR_QUAD_CurrentVersionRun_60b5 {
  strings:
    $key_60b5 = { 33 da [2] 17 d4 [2] 3c f8 [2] 12 da [2] 06 c1 [2] 09 db [2] 17 c6 [2] 15 c7 [2] 0e c1 [2] 12 c6 [2] 0e e9 }

  condition:
    any of them
}