rule TTP_XOR_QUAD_CurrentVersionRun_02a5 {
  strings:
    $key_02a5 = { 51 ca [2] 75 c4 [2] 5e e8 [2] 70 ca [2] 64 d1 [2] 6b cb [2] 75 d6 [2] 77 d7 [2] 6c d1 [2] 70 d6 [2] 6c f9 }

  condition:
    any of them
}