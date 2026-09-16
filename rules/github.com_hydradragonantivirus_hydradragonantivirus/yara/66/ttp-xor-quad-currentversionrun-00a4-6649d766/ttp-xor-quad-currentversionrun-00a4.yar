rule TTP_XOR_QUAD_CurrentVersionRun_00a4 {
  strings:
    $key_00a4 = { 53 cb [2] 77 c5 [2] 5c e9 [2] 72 cb [2] 66 d0 [2] 69 ca [2] 77 d7 [2] 75 d6 [2] 6e d0 [2] 72 d7 [2] 6e f8 }

  condition:
    any of them
}