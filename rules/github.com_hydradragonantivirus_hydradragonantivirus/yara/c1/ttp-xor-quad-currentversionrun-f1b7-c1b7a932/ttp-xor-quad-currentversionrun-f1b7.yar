rule TTP_XOR_QUAD_CurrentVersionRun_f1b7 {
  strings:
    $key_f1b7 = { a2 d8 [2] 86 d6 [2] ad fa [2] 83 d8 [2] 97 c3 [2] 98 d9 [2] 86 c4 [2] 84 c5 [2] 9f c3 [2] 83 c4 [2] 9f eb }

  condition:
    any of them
}