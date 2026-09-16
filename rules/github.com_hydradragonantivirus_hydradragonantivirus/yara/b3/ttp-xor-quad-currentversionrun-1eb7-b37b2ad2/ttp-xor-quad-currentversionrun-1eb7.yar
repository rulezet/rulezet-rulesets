rule TTP_XOR_QUAD_CurrentVersionRun_1eb7 {
  strings:
    $key_1eb7 = { 4d d8 [2] 69 d6 [2] 42 fa [2] 6c d8 [2] 78 c3 [2] 77 d9 [2] 69 c4 [2] 6b c5 [2] 70 c3 [2] 6c c4 [2] 70 eb }

  condition:
    any of them
}