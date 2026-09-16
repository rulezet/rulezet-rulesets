rule TTP_XOR_QUAD_CurrentVersionRun_46b7 {
  strings:
    $key_46b7 = { 15 d8 [2] 31 d6 [2] 1a fa [2] 34 d8 [2] 20 c3 [2] 2f d9 [2] 31 c4 [2] 33 c5 [2] 28 c3 [2] 34 c4 [2] 28 eb }

  condition:
    any of them
}