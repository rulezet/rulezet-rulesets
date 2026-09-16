rule TTP_XOR_QUAD_CurrentVersionRun_fea8 {
  strings:
    $key_fea8 = { ad c7 [2] 89 c9 [2] a2 e5 [2] 8c c7 [2] 98 dc [2] 97 c6 [2] 89 db [2] 8b da [2] 90 dc [2] 8c db [2] 90 f4 }

  condition:
    any of them
}