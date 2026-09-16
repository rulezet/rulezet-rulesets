rule TTP_XOR_QUAD_CurrentVersionRun_1aad {
  strings:
    $key_1aad = { 49 c2 [2] 6d cc [2] 46 e0 [2] 68 c2 [2] 7c d9 [2] 73 c3 [2] 6d de [2] 6f df [2] 74 d9 [2] 68 de [2] 74 f1 }

  condition:
    any of them
}