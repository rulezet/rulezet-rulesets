rule TTP_XOR_QUAD_CurrentVersionRun_e7a5 {
  strings:
    $key_e7a5 = { b4 ca [2] 90 c4 [2] bb e8 [2] 95 ca [2] 81 d1 [2] 8e cb [2] 90 d6 [2] 92 d7 [2] 89 d1 [2] 95 d6 [2] 89 f9 }

  condition:
    any of them
}