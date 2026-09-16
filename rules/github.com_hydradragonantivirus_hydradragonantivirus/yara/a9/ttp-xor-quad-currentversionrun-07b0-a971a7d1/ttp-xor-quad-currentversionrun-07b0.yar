rule TTP_XOR_QUAD_CurrentVersionRun_07b0 {
  strings:
    $key_07b0 = { 54 df [2] 70 d1 [2] 5b fd [2] 75 df [2] 61 c4 [2] 6e de [2] 70 c3 [2] 72 c2 [2] 69 c4 [2] 75 c3 [2] 69 ec }

  condition:
    any of them
}