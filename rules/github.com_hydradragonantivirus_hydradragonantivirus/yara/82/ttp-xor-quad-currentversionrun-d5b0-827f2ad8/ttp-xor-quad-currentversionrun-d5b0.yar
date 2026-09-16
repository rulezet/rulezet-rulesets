rule TTP_XOR_QUAD_CurrentVersionRun_d5b0 {
  strings:
    $key_d5b0 = { 86 df [2] a2 d1 [2] 89 fd [2] a7 df [2] b3 c4 [2] bc de [2] a2 c3 [2] a0 c2 [2] bb c4 [2] a7 c3 [2] bb ec }

  condition:
    any of them
}