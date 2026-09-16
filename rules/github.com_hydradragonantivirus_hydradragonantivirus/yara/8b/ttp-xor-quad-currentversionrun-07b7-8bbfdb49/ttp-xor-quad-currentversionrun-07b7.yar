rule TTP_XOR_QUAD_CurrentVersionRun_07b7 {
  strings:
    $key_07b7 = { 54 d8 [2] 70 d6 [2] 5b fa [2] 75 d8 [2] 61 c3 [2] 6e d9 [2] 70 c4 [2] 72 c5 [2] 69 c3 [2] 75 c4 [2] 69 eb }

  condition:
    any of them
}