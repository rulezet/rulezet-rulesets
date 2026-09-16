rule TTP_XOR_QUAD_CurrentVersionRun_e7b7 {
  strings:
    $key_e7b7 = { b4 d8 [2] 90 d6 [2] bb fa [2] 95 d8 [2] 81 c3 [2] 8e d9 [2] 90 c4 [2] 92 c5 [2] 89 c3 [2] 95 c4 [2] 89 eb }

  condition:
    any of them
}