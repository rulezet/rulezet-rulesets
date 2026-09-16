rule TTP_XOR_QUAD_CurrentVersionRun_0eb7 {
  strings:
    $key_0eb7 = { 5d d8 [2] 79 d6 [2] 52 fa [2] 7c d8 [2] 68 c3 [2] 67 d9 [2] 79 c4 [2] 7b c5 [2] 60 c3 [2] 7c c4 [2] 60 eb }

  condition:
    any of them
}