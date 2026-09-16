rule TTP_XOR_QUAD_CurrentVersionRun_ceb0 {
  strings:
    $key_ceb0 = { 9d df [2] b9 d1 [2] 92 fd [2] bc df [2] a8 c4 [2] a7 de [2] b9 c3 [2] bb c2 [2] a0 c4 [2] bc c3 [2] a0 ec }

  condition:
    any of them
}