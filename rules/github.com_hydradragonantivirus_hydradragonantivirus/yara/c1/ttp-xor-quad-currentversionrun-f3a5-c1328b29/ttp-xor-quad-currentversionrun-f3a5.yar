rule TTP_XOR_QUAD_CurrentVersionRun_f3a5 {
  strings:
    $key_f3a5 = { a0 ca [2] 84 c4 [2] af e8 [2] 81 ca [2] 95 d1 [2] 9a cb [2] 84 d6 [2] 86 d7 [2] 9d d1 [2] 81 d6 [2] 9d f9 }

  condition:
    any of them
}