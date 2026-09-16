rule TTP_XOR_QUAD_CurrentVersionRun_51b7 {
  strings:
    $key_51b7 = { 02 d8 [2] 26 d6 [2] 0d fa [2] 23 d8 [2] 37 c3 [2] 38 d9 [2] 26 c4 [2] 24 c5 [2] 3f c3 [2] 23 c4 [2] 3f eb }

  condition:
    any of them
}