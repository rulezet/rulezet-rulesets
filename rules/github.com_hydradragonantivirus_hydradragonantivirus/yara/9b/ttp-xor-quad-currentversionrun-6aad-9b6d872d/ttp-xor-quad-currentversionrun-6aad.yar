rule TTP_XOR_QUAD_CurrentVersionRun_6aad {
  strings:
    $key_6aad = { 39 c2 [2] 1d cc [2] 36 e0 [2] 18 c2 [2] 0c d9 [2] 03 c3 [2] 1d de [2] 1f df [2] 04 d9 [2] 18 de [2] 04 f1 }

  condition:
    any of them
}