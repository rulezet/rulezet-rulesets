rule TTP_XOR_QUAD_CurrentVersionRun_7aad {
  strings:
    $key_7aad = { 29 c2 [2] 0d cc [2] 26 e0 [2] 08 c2 [2] 1c d9 [2] 13 c3 [2] 0d de [2] 0f df [2] 14 d9 [2] 08 de [2] 14 f1 }

  condition:
    any of them
}