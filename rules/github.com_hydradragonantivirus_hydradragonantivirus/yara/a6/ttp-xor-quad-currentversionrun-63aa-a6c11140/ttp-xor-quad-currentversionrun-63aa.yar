rule TTP_XOR_QUAD_CurrentVersionRun_63aa {
  strings:
    $key_63aa = { 30 c5 [2] 14 cb [2] 3f e7 [2] 11 c5 [2] 05 de [2] 0a c4 [2] 14 d9 [2] 16 d8 [2] 0d de [2] 11 d9 [2] 0d f6 }

  condition:
    any of them
}