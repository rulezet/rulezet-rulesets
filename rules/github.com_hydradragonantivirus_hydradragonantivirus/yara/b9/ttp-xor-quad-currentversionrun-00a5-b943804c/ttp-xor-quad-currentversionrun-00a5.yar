rule TTP_XOR_QUAD_CurrentVersionRun_00a5 {
  strings:
    $key_00a5 = { 53 ca [2] 77 c4 [2] 5c e8 [2] 72 ca [2] 66 d1 [2] 69 cb [2] 77 d6 [2] 75 d7 [2] 6e d1 [2] 72 d6 [2] 6e f9 }

  condition:
    any of them
}