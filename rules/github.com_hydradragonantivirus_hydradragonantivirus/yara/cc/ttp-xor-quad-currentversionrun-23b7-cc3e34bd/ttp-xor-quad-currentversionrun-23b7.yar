rule TTP_XOR_QUAD_CurrentVersionRun_23b7 {
  strings:
    $key_23b7 = { 70 d8 [2] 54 d6 [2] 7f fa [2] 51 d8 [2] 45 c3 [2] 4a d9 [2] 54 c4 [2] 56 c5 [2] 4d c3 [2] 51 c4 [2] 4d eb }

  condition:
    any of them
}