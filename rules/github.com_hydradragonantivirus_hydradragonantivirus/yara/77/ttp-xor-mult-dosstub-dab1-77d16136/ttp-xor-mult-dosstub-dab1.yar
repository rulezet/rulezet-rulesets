rule TTP_XOR_MULT_DOSStub_dab1 {
  strings:
    $key_dab1 = { 8e d9 [2] fa c1 [2] bd c3 [2] fa d2 [2] b4 de [2] b8 d4 [2] af df [2] b4 91 [2] 89 }

  condition:
    any of them
}