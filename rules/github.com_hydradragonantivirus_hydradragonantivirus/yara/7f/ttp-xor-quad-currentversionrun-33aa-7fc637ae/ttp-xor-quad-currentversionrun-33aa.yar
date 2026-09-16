rule TTP_XOR_QUAD_CurrentVersionRun_33aa {
  strings:
    $key_33aa = { 60 c5 [2] 44 cb [2] 6f e7 [2] 41 c5 [2] 55 de [2] 5a c4 [2] 44 d9 [2] 46 d8 [2] 5d de [2] 41 d9 [2] 5d f6 }

  condition:
    any of them
}