rule TTP_XOR_QUAD_CurrentVersionRun_55b7 {
  strings:
    $key_55b7 = { 06 d8 [2] 22 d6 [2] 09 fa [2] 27 d8 [2] 33 c3 [2] 3c d9 [2] 22 c4 [2] 20 c5 [2] 3b c3 [2] 27 c4 [2] 3b eb }

  condition:
    any of them
}