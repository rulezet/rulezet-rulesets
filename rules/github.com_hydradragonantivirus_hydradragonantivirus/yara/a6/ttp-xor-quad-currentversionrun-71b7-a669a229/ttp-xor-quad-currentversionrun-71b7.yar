rule TTP_XOR_QUAD_CurrentVersionRun_71b7 {
  strings:
    $key_71b7 = { 22 d8 [2] 06 d6 [2] 2d fa [2] 03 d8 [2] 17 c3 [2] 18 d9 [2] 06 c4 [2] 04 c5 [2] 1f c3 [2] 03 c4 [2] 1f eb }

  condition:
    any of them
}