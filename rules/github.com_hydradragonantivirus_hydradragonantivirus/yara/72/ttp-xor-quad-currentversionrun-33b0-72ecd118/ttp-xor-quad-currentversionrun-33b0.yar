rule TTP_XOR_QUAD_CurrentVersionRun_33b0 {
  strings:
    $key_33b0 = { 60 df [2] 44 d1 [2] 6f fd [2] 41 df [2] 55 c4 [2] 5a de [2] 44 c3 [2] 46 c2 [2] 5d c4 [2] 41 c3 [2] 5d ec }

  condition:
    any of them
}