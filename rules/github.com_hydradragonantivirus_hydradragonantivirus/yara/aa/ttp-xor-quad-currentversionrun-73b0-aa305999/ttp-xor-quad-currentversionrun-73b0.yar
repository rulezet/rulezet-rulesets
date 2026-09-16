rule TTP_XOR_QUAD_CurrentVersionRun_73b0 {
  strings:
    $key_73b0 = { 20 df [2] 04 d1 [2] 2f fd [2] 01 df [2] 15 c4 [2] 1a de [2] 04 c3 [2] 06 c2 [2] 1d c4 [2] 01 c3 [2] 1d ec }

  condition:
    any of them
}