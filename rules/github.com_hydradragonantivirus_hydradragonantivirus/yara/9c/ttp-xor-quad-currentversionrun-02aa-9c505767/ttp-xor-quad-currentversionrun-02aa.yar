rule TTP_XOR_QUAD_CurrentVersionRun_02aa {
  strings:
    $key_02aa = { 51 c5 [2] 75 cb [2] 5e e7 [2] 70 c5 [2] 64 de [2] 6b c4 [2] 75 d9 [2] 77 d8 [2] 6c de [2] 70 d9 [2] 6c f6 }

  condition:
    any of them
}