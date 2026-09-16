rule TTP_XOR_QUAD_CurrentVersionRun_0cad {
  strings:
    $key_0cad = { 5f c2 [2] 7b cc [2] 50 e0 [2] 7e c2 [2] 6a d9 [2] 65 c3 [2] 7b de [2] 79 df [2] 62 d9 [2] 7e de [2] 62 f1 }

  condition:
    any of them
}