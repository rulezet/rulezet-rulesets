rule TTP_XOR_QUAD_CurrentVersionRun_0ea8 {
  strings:
    $key_0ea8 = { 5d c7 [2] 79 c9 [2] 52 e5 [2] 7c c7 [2] 68 dc [2] 67 c6 [2] 79 db [2] 7b da [2] 60 dc [2] 7c db [2] 60 f4 }

  condition:
    any of them
}