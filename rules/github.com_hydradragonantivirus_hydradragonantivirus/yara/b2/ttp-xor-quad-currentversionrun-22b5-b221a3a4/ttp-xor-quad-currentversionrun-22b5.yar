rule TTP_XOR_QUAD_CurrentVersionRun_22b5 {
  strings:
    $key_22b5 = { 71 da [2] 55 d4 [2] 7e f8 [2] 50 da [2] 44 c1 [2] 4b db [2] 55 c6 [2] 57 c7 [2] 4c c1 [2] 50 c6 [2] 4c e9 }

  condition:
    any of them
}