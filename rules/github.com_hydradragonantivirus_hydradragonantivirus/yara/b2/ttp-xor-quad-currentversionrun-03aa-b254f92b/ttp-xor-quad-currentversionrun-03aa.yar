rule TTP_XOR_QUAD_CurrentVersionRun_03aa {
  strings:
    $key_03aa = { 50 c5 [2] 74 cb [2] 5f e7 [2] 71 c5 [2] 65 de [2] 6a c4 [2] 74 d9 [2] 76 d8 [2] 6d de [2] 71 d9 [2] 6d f6 }

  condition:
    any of them
}