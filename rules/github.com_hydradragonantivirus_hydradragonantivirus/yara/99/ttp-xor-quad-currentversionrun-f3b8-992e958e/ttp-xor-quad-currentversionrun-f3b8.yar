rule TTP_XOR_QUAD_CurrentVersionRun_f3b8 {
  strings:
    $key_f3b8 = { a0 d7 [2] 84 d9 [2] af f5 [2] 81 d7 [2] 95 cc [2] 9a d6 [2] 84 cb [2] 86 ca [2] 9d cc [2] 81 cb [2] 9d e4 }

  condition:
    any of them
}