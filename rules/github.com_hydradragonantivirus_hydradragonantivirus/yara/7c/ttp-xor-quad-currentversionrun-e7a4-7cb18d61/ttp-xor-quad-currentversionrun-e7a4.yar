rule TTP_XOR_QUAD_CurrentVersionRun_e7a4 {
  strings:
    $key_e7a4 = { b4 cb [2] 90 c5 [2] bb e9 [2] 95 cb [2] 81 d0 [2] 8e ca [2] 90 d7 [2] 92 d6 [2] 89 d0 [2] 95 d7 [2] 89 f8 }

  condition:
    any of them
}