rule TTP_XOR_QUAD_CurrentVersionRun_02a4 {
  strings:
    $key_02a4 = { 51 cb [2] 75 c5 [2] 5e e9 [2] 70 cb [2] 64 d0 [2] 6b ca [2] 75 d7 [2] 77 d6 [2] 6c d0 [2] 70 d7 [2] 6c f8 }

  condition:
    any of them
}