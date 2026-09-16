rule TTP_XOR_QUAD_CurrentVersionRun_63b0 {
  strings:
    $key_63b0 = { 30 df [2] 14 d1 [2] 3f fd [2] 11 df [2] 05 c4 [2] 0a de [2] 14 c3 [2] 16 c2 [2] 0d c4 [2] 11 c3 [2] 0d ec }

  condition:
    any of them
}