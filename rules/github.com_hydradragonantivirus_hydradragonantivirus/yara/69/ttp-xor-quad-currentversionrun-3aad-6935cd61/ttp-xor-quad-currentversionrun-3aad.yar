rule TTP_XOR_QUAD_CurrentVersionRun_3aad {
  strings:
    $key_3aad = { 69 c2 [2] 4d cc [2] 66 e0 [2] 48 c2 [2] 5c d9 [2] 53 c3 [2] 4d de [2] 4f df [2] 54 d9 [2] 48 de [2] 54 f1 }

  condition:
    any of them
}