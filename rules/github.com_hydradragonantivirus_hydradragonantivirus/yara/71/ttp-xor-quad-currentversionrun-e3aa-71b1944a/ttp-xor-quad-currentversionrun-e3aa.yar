rule TTP_XOR_QUAD_CurrentVersionRun_e3aa {
  strings:
    $key_e3aa = { b0 c5 [2] 94 cb [2] bf e7 [2] 91 c5 [2] 85 de [2] 8a c4 [2] 94 d9 [2] 96 d8 [2] 8d de [2] 91 d9 [2] 8d f6 }

  condition:
    any of them
}