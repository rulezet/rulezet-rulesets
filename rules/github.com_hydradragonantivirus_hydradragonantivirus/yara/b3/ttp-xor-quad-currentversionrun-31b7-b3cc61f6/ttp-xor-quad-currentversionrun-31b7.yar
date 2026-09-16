rule TTP_XOR_QUAD_CurrentVersionRun_31b7 {
  strings:
    $key_31b7 = { 62 d8 [2] 46 d6 [2] 6d fa [2] 43 d8 [2] 57 c3 [2] 58 d9 [2] 46 c4 [2] 44 c5 [2] 5f c3 [2] 43 c4 [2] 5f eb }

  condition:
    any of them
}