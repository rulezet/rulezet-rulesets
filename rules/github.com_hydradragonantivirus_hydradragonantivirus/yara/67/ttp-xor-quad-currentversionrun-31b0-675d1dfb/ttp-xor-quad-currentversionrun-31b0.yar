rule TTP_XOR_QUAD_CurrentVersionRun_31b0 {
  strings:
    $key_31b0 = { 62 df [2] 46 d1 [2] 6d fd [2] 43 df [2] 57 c4 [2] 58 de [2] 46 c3 [2] 44 c2 [2] 5f c4 [2] 43 c3 [2] 5f ec }

  condition:
    any of them
}