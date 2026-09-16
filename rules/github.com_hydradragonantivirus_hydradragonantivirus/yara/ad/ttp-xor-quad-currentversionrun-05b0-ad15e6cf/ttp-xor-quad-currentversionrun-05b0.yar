rule TTP_XOR_QUAD_CurrentVersionRun_05b0 {
  strings:
    $key_05b0 = { 56 df [2] 72 d1 [2] 59 fd [2] 77 df [2] 63 c4 [2] 6c de [2] 72 c3 [2] 70 c2 [2] 6b c4 [2] 77 c3 [2] 6b ec }

  condition:
    any of them
}