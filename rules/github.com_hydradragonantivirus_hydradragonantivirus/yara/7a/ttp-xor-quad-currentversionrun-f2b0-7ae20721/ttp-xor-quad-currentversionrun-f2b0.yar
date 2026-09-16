rule TTP_XOR_QUAD_CurrentVersionRun_f2b0 {
  strings:
    $key_f2b0 = { a1 df [2] 85 d1 [2] ae fd [2] 80 df [2] 94 c4 [2] 9b de [2] 85 c3 [2] 87 c2 [2] 9c c4 [2] 80 c3 [2] 9c ec }

  condition:
    any of them
}