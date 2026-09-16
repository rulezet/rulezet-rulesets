rule TTP_XOR_MULT_DOSStub_dab0 {
  strings:
    $key_dab0 = { 8e d8 [2] fa c0 [2] bd c2 [2] fa d3 [2] b4 df [2] b8 d5 [2] af de [2] b4 90 [2] 89 }

  condition:
    any of them
}