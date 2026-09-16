rule TTP_XOR_QUAD_CurrentVersionRun_60b4 {
  strings:
    $key_60b4 = { 33 db [2] 17 d5 [2] 3c f9 [2] 12 db [2] 06 c0 [2] 09 da [2] 17 c7 [2] 15 c6 [2] 0e c0 [2] 12 c7 [2] 0e e8 }

  condition:
    any of them
}