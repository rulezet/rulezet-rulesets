rule TTP_XOR_QUAD_CurrentVersionRun_22b4 {
  strings:
    $key_22b4 = { 71 db [2] 55 d5 [2] 7e f9 [2] 50 db [2] 44 c0 [2] 4b da [2] 55 c7 [2] 57 c6 [2] 4c c0 [2] 50 c7 [2] 4c e8 }

  condition:
    any of them
}