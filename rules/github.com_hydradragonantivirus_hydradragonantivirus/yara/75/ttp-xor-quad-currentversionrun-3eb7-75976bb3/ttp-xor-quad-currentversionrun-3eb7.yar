rule TTP_XOR_QUAD_CurrentVersionRun_3eb7 {
  strings:
    $key_3eb7 = { 6d d8 [2] 49 d6 [2] 62 fa [2] 4c d8 [2] 58 c3 [2] 57 d9 [2] 49 c4 [2] 4b c5 [2] 50 c3 [2] 4c c4 [2] 50 eb }

  condition:
    any of them
}