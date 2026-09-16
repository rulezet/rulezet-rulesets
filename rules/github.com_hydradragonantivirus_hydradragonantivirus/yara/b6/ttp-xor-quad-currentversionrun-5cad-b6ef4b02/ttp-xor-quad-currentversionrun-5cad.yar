rule TTP_XOR_QUAD_CurrentVersionRun_5cad {
  strings:
    $key_5cad = { 0f c2 [2] 2b cc [2] 00 e0 [2] 2e c2 [2] 3a d9 [2] 35 c3 [2] 2b de [2] 29 df [2] 32 d9 [2] 2e de [2] 32 f1 }

  condition:
    any of them
}