rule TTP_XOR_QUAD_CurrentVersionRun_42a5 {
  strings:
    $key_42a5 = { 11 ca [2] 35 c4 [2] 1e e8 [2] 30 ca [2] 24 d1 [2] 2b cb [2] 35 d6 [2] 37 d7 [2] 2c d1 [2] 30 d6 [2] 2c f9 }

  condition:
    any of them
}