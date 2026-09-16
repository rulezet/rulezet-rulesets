rule TTP_XOR_QUAD_CurrentVersionRun_53aa {
  strings:
    $key_53aa = { 00 c5 [2] 24 cb [2] 0f e7 [2] 21 c5 [2] 35 de [2] 3a c4 [2] 24 d9 [2] 26 d8 [2] 3d de [2] 21 d9 [2] 3d f6 }

  condition:
    any of them
}