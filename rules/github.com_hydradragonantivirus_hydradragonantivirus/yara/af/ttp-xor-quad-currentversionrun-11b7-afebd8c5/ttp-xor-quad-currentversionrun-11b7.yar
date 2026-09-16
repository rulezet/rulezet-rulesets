rule TTP_XOR_QUAD_CurrentVersionRun_11b7 {
  strings:
    $key_11b7 = { 42 d8 [2] 66 d6 [2] 4d fa [2] 63 d8 [2] 77 c3 [2] 78 d9 [2] 66 c4 [2] 64 c5 [2] 7f c3 [2] 63 c4 [2] 7f eb }

  condition:
    any of them
}