rule TTP_XOR_QUAD_CurrentVersionRun_33b7 {
  strings:
    $key_33b7 = { 60 d8 [2] 44 d6 [2] 6f fa [2] 41 d8 [2] 55 c3 [2] 5a d9 [2] 44 c4 [2] 46 c5 [2] 5d c3 [2] 41 c4 [2] 5d eb }

  condition:
    any of them
}