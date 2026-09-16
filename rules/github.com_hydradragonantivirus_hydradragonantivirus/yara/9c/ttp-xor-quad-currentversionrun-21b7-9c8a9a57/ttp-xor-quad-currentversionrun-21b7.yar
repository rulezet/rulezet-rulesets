rule TTP_XOR_QUAD_CurrentVersionRun_21b7 {
  strings:
    $key_21b7 = { 72 d8 [2] 56 d6 [2] 7d fa [2] 53 d8 [2] 47 c3 [2] 48 d9 [2] 56 c4 [2] 54 c5 [2] 4f c3 [2] 53 c4 [2] 4f eb }

  condition:
    any of them
}