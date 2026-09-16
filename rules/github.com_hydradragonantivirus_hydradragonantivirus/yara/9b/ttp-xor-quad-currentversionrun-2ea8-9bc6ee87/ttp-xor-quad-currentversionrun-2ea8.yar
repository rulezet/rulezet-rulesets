rule TTP_XOR_QUAD_CurrentVersionRun_2ea8 {
  strings:
    $key_2ea8 = { 7d c7 [2] 59 c9 [2] 72 e5 [2] 5c c7 [2] 48 dc [2] 47 c6 [2] 59 db [2] 5b da [2] 40 dc [2] 5c db [2] 40 f4 }

  condition:
    any of them
}