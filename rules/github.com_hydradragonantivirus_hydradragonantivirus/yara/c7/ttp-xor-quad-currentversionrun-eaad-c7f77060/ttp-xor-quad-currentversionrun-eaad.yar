rule TTP_XOR_QUAD_CurrentVersionRun_eaad {
  strings:
    $key_eaad = { b9 c2 [2] 9d cc [2] b6 e0 [2] 98 c2 [2] 8c d9 [2] 83 c3 [2] 9d de [2] 9f df [2] 84 d9 [2] 98 de [2] 84 f1 }

  condition:
    any of them
}