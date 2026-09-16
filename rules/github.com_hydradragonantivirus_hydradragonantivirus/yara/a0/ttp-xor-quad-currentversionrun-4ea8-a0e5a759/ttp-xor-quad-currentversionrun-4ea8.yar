rule TTP_XOR_QUAD_CurrentVersionRun_4ea8 {
  strings:
    $key_4ea8 = { 1d c7 [2] 39 c9 [2] 12 e5 [2] 3c c7 [2] 28 dc [2] 27 c6 [2] 39 db [2] 3b da [2] 20 dc [2] 3c db [2] 20 f4 }

  condition:
    any of them
}