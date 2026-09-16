rule TTP_XOR_QUAD_CurrentVersionRun_67b0 {
  strings:
    $key_67b0 = { 34 df [2] 10 d1 [2] 3b fd [2] 15 df [2] 01 c4 [2] 0e de [2] 10 c3 [2] 12 c2 [2] 09 c4 [2] 15 c3 [2] 09 ec }

  condition:
    any of them
}