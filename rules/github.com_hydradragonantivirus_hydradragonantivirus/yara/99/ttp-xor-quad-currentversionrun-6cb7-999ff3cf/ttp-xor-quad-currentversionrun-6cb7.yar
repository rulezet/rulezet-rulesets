rule TTP_XOR_QUAD_CurrentVersionRun_6cb7 {
  strings:
    $key_6cb7 = { 3f d8 [2] 1b d6 [2] 30 fa [2] 1e d8 [2] 0a c3 [2] 05 d9 [2] 1b c4 [2] 19 c5 [2] 02 c3 [2] 1e c4 [2] 02 eb }

  condition:
    any of them
}