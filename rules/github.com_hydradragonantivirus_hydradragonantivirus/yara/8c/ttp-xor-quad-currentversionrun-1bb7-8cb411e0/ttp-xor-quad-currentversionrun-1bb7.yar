rule TTP_XOR_QUAD_CurrentVersionRun_1bb7 {
  strings:
    $key_1bb7 = { 48 d8 [2] 6c d6 [2] 47 fa [2] 69 d8 [2] 7d c3 [2] 72 d9 [2] 6c c4 [2] 6e c5 [2] 75 c3 [2] 69 c4 [2] 75 eb }

  condition:
    any of them
}