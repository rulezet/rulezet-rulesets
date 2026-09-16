rule TTP_XOR_QUAD_CurrentVersionRun_f3a4 {
  strings:
    $key_f3a4 = { a0 cb [2] 84 c5 [2] af e9 [2] 81 cb [2] 95 d0 [2] 9a ca [2] 84 d7 [2] 86 d6 [2] 9d d0 [2] 81 d7 [2] 9d f8 }

  condition:
    any of them
}