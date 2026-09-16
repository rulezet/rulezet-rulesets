rule TTP_XOR_MULT_DOSStub_dab5 {
  strings:
    $key_dab5 = { 8e dd [2] fa c5 [2] bd c7 [2] fa d6 [2] b4 da [2] b8 d0 [2] af db [2] b4 95 [2] 89 }

  condition:
    any of them
}