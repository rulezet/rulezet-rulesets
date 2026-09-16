rule TTP_XOR_QUAD_CurrentVersionRun_ceb1 {
  strings:
    $key_ceb1 = { 9d de [2] b9 d0 [2] 92 fc [2] bc de [2] a8 c5 [2] a7 df [2] b9 c2 [2] bb c3 [2] a0 c5 [2] bc c2 [2] a0 ed }

  condition:
    any of them
}