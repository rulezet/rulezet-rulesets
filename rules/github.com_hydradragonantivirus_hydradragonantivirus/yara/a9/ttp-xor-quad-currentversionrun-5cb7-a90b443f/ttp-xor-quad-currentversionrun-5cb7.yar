rule TTP_XOR_QUAD_CurrentVersionRun_5cb7 {
  strings:
    $key_5cb7 = { 0f d8 [2] 2b d6 [2] 00 fa [2] 2e d8 [2] 3a c3 [2] 35 d9 [2] 2b c4 [2] 29 c5 [2] 32 c3 [2] 2e c4 [2] 32 eb }

  condition:
    any of them
}