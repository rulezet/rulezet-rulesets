rule TTP_XOR_QUAD_CurrentVersionRun_75b0 {
  strings:
    $key_75b0 = { 26 df [2] 02 d1 [2] 29 fd [2] 07 df [2] 13 c4 [2] 1c de [2] 02 c3 [2] 00 c2 [2] 1b c4 [2] 07 c3 [2] 1b ec }

  condition:
    any of them
}