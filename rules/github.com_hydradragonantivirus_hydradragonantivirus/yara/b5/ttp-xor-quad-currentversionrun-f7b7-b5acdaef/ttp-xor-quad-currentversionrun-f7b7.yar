rule TTP_XOR_QUAD_CurrentVersionRun_f7b7 {
  strings:
    $key_f7b7 = { a4 d8 [2] 80 d6 [2] ab fa [2] 85 d8 [2] 91 c3 [2] 9e d9 [2] 80 c4 [2] 82 c5 [2] 99 c3 [2] 85 c4 [2] 99 eb }

  condition:
    any of them
}