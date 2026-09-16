rule TTP_XOR_QUAD_CurrentVersionRun_13aa {
  strings:
    $key_13aa = { 40 c5 [2] 64 cb [2] 4f e7 [2] 61 c5 [2] 75 de [2] 7a c4 [2] 64 d9 [2] 66 d8 [2] 7d de [2] 61 d9 [2] 7d f6 }

  condition:
    any of them
}