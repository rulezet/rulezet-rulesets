rule TTP_XOR_QUAD_CurrentVersionRun_ebb0 {
  strings:
    $key_ebb0 = { b8 df [2] 9c d1 [2] b7 fd [2] 99 df [2] 8d c4 [2] 82 de [2] 9c c3 [2] 9e c2 [2] 85 c4 [2] 99 c3 [2] 85 ec }

  condition:
    any of them
}