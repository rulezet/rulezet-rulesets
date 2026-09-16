rule TTP_XOR_QUAD_CurrentVersionRun_50a4 {
  strings:
    $key_50a4 = { 03 cb [2] 27 c5 [2] 0c e9 [2] 22 cb [2] 36 d0 [2] 39 ca [2] 27 d7 [2] 25 d6 [2] 3e d0 [2] 22 d7 [2] 3e f8 }

  condition:
    any of them
}