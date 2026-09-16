rule TTP_XOR_QUAD_CurrentVersionRun_1cb7 {
  strings:
    $key_1cb7 = { 4f d8 [2] 6b d6 [2] 40 fa [2] 6e d8 [2] 7a c3 [2] 75 d9 [2] 6b c4 [2] 69 c5 [2] 72 c3 [2] 6e c4 [2] 72 eb }

  condition:
    any of them
}