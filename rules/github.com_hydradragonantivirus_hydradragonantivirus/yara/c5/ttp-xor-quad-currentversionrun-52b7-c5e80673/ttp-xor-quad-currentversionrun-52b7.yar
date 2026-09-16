rule TTP_XOR_QUAD_CurrentVersionRun_52b7 {
  strings:
    $key_52b7 = { 01 d8 [2] 25 d6 [2] 0e fa [2] 20 d8 [2] 34 c3 [2] 3b d9 [2] 25 c4 [2] 27 c5 [2] 3c c3 [2] 20 c4 [2] 3c eb }

  condition:
    any of them
}