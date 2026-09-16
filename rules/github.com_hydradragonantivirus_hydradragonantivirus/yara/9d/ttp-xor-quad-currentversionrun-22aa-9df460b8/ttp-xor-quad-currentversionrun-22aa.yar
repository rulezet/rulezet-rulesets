rule TTP_XOR_QUAD_CurrentVersionRun_22aa {
  strings:
    $key_22aa = { 71 c5 [2] 55 cb [2] 7e e7 [2] 50 c5 [2] 44 de [2] 4b c4 [2] 55 d9 [2] 57 d8 [2] 4c de [2] 50 d9 [2] 4c f6 }

  condition:
    any of them
}