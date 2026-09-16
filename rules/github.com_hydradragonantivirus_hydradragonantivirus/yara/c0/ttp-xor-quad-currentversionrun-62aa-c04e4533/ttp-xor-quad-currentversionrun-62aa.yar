rule TTP_XOR_QUAD_CurrentVersionRun_62aa {
  strings:
    $key_62aa = { 31 c5 [2] 15 cb [2] 3e e7 [2] 10 c5 [2] 04 de [2] 0b c4 [2] 15 d9 [2] 17 d8 [2] 0c de [2] 10 d9 [2] 0c f6 }

  condition:
    any of them
}