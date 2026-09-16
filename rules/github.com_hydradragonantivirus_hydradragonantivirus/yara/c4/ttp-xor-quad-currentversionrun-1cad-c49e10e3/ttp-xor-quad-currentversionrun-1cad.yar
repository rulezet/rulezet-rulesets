rule TTP_XOR_QUAD_CurrentVersionRun_1cad {
  strings:
    $key_1cad = { 4f c2 [2] 6b cc [2] 40 e0 [2] 6e c2 [2] 7a d9 [2] 75 c3 [2] 6b de [2] 69 df [2] 72 d9 [2] 6e de [2] 72 f1 }

  condition:
    any of them
}