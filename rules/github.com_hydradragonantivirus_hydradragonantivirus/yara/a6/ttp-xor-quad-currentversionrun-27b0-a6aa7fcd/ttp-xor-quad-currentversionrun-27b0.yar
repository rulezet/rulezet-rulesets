rule TTP_XOR_QUAD_CurrentVersionRun_27b0 {
  strings:
    $key_27b0 = { 74 df [2] 50 d1 [2] 7b fd [2] 55 df [2] 41 c4 [2] 4e de [2] 50 c3 [2] 52 c2 [2] 49 c4 [2] 55 c3 [2] 49 ec }

  condition:
    any of them
}