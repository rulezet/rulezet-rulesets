rule TTP_XOR_QUAD_CurrentVersionRun_55b0 {
  strings:
    $key_55b0 = { 06 df [2] 22 d1 [2] 09 fd [2] 27 df [2] 33 c4 [2] 3c de [2] 22 c3 [2] 20 c2 [2] 3b c4 [2] 27 c3 [2] 3b ec }

  condition:
    any of them
}