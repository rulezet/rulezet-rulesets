rule TTP_XOR_QUAD_CurrentVersionRun_01b7 {
  strings:
    $key_01b7 = { 52 d8 [2] 76 d6 [2] 5d fa [2] 73 d8 [2] 67 c3 [2] 68 d9 [2] 76 c4 [2] 74 c5 [2] 6f c3 [2] 73 c4 [2] 6f eb }

  condition:
    any of them
}