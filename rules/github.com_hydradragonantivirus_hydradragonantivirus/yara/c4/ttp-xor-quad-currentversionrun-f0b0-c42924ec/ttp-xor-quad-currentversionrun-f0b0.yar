rule TTP_XOR_QUAD_CurrentVersionRun_f0b0 {
  strings:
    $key_f0b0 = { a3 df [2] 87 d1 [2] ac fd [2] 82 df [2] 96 c4 [2] 99 de [2] 87 c3 [2] 85 c2 [2] 9e c4 [2] 82 c3 [2] 9e ec }

  condition:
    any of them
}