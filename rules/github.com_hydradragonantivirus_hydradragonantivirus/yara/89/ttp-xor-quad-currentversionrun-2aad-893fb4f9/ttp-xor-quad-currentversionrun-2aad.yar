rule TTP_XOR_QUAD_CurrentVersionRun_2aad {
  strings:
    $key_2aad = { 79 c2 [2] 5d cc [2] 76 e0 [2] 58 c2 [2] 4c d9 [2] 43 c3 [2] 5d de [2] 5f df [2] 44 d9 [2] 58 de [2] 44 f1 }

  condition:
    any of them
}