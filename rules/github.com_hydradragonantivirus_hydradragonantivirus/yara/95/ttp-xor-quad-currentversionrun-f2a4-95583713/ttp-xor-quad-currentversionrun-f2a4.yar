rule TTP_XOR_QUAD_CurrentVersionRun_f2a4 {
  strings:
    $key_f2a4 = { a1 cb [2] 85 c5 [2] ae e9 [2] 80 cb [2] 94 d0 [2] 9b ca [2] 85 d7 [2] 87 d6 [2] 9c d0 [2] 80 d7 [2] 9c f8 }

  condition:
    any of them
}