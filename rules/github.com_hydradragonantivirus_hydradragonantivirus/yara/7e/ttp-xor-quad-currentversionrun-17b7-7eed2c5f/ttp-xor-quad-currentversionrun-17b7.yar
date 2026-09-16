rule TTP_XOR_QUAD_CurrentVersionRun_17b7 {
  strings:
    $key_17b7 = { 44 d8 [2] 60 d6 [2] 4b fa [2] 65 d8 [2] 71 c3 [2] 7e d9 [2] 60 c4 [2] 62 c5 [2] 79 c3 [2] 65 c4 [2] 79 eb }

  condition:
    any of them
}