rule TTP_XOR_QUAD_CurrentVersionRun_10b7 {
  strings:
    $key_10b7 = { 43 d8 [2] 67 d6 [2] 4c fa [2] 62 d8 [2] 76 c3 [2] 79 d9 [2] 67 c4 [2] 65 c5 [2] 7e c3 [2] 62 c4 [2] 7e eb }

  condition:
    any of them
}