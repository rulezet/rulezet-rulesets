rule TTP_XOR_QUAD_CurrentVersionRun_2cad {
  strings:
    $key_2cad = { 7f c2 [2] 5b cc [2] 70 e0 [2] 5e c2 [2] 4a d9 [2] 45 c3 [2] 5b de [2] 59 df [2] 42 d9 [2] 5e de [2] 42 f1 }

  condition:
    any of them
}