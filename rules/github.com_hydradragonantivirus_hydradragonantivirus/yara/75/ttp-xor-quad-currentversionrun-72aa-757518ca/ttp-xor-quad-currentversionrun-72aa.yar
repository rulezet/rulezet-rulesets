rule TTP_XOR_QUAD_CurrentVersionRun_72aa {
  strings:
    $key_72aa = { 21 c5 [2] 05 cb [2] 2e e7 [2] 00 c5 [2] 14 de [2] 1b c4 [2] 05 d9 [2] 07 d8 [2] 1c de [2] 00 d9 [2] 1c f6 }

  condition:
    any of them
}