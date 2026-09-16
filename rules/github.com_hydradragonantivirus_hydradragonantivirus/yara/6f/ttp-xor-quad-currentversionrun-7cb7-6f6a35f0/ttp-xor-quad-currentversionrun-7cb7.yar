rule TTP_XOR_QUAD_CurrentVersionRun_7cb7 {
  strings:
    $key_7cb7 = { 2f d8 [2] 0b d6 [2] 20 fa [2] 0e d8 [2] 1a c3 [2] 15 d9 [2] 0b c4 [2] 09 c5 [2] 12 c3 [2] 0e c4 [2] 12 eb }

  condition:
    any of them
}