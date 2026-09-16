rule TTP_XOR_QUAD_CurrentVersionRun_7cad {
  strings:
    $key_7cad = { 2f c2 [2] 0b cc [2] 20 e0 [2] 0e c2 [2] 1a d9 [2] 15 c3 [2] 0b de [2] 09 df [2] 12 d9 [2] 0e de [2] 12 f1 }

  condition:
    any of them
}