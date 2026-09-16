rule TTP_XOR_QUAD_CurrentVersionRun_5db0 {
  strings:
    $key_5db0 = { 0e df [2] 2a d1 [2] 01 fd [2] 2f df [2] 3b c4 [2] 34 de [2] 2a c3 [2] 28 c2 [2] 33 c4 [2] 2f c3 [2] 33 ec }

  condition:
    any of them
}