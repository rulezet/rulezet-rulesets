rule TTP_XOR_QUAD_CurrentVersionRun_13b0 {
  strings:
    $key_13b0 = { 40 df [2] 64 d1 [2] 4f fd [2] 61 df [2] 75 c4 [2] 7a de [2] 64 c3 [2] 66 c2 [2] 7d c4 [2] 61 c3 [2] 7d ec }

  condition:
    any of them
}