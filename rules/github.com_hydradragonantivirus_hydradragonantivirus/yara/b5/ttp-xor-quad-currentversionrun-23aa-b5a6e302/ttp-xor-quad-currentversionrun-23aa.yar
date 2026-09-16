rule TTP_XOR_QUAD_CurrentVersionRun_23aa {
  strings:
    $key_23aa = { 70 c5 [2] 54 cb [2] 7f e7 [2] 51 c5 [2] 45 de [2] 4a c4 [2] 54 d9 [2] 56 d8 [2] 4d de [2] 51 d9 [2] 4d f6 }

  condition:
    any of them
}