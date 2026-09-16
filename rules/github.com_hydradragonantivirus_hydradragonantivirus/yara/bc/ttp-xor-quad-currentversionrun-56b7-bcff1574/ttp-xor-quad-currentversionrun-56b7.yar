rule TTP_XOR_QUAD_CurrentVersionRun_56b7 {
  strings:
    $key_56b7 = { 05 d8 [2] 21 d6 [2] 0a fa [2] 24 d8 [2] 30 c3 [2] 3f d9 [2] 21 c4 [2] 23 c5 [2] 38 c3 [2] 24 c4 [2] 38 eb }

  condition:
    any of them
}