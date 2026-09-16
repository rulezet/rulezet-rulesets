rule TTP_XOR_QUAD_CurrentVersionRun_73aa {
  strings:
    $key_73aa = { 20 c5 [2] 04 cb [2] 2f e7 [2] 01 c5 [2] 15 de [2] 1a c4 [2] 04 d9 [2] 06 d8 [2] 1d de [2] 01 d9 [2] 1d f6 }

  condition:
    any of them
}