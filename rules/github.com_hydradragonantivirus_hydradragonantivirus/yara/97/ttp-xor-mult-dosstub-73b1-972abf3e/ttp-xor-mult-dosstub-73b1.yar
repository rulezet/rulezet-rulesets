rule TTP_XOR_MULT_DOSStub_73b1 {
  strings:
    $key_73b1 = { 27 d9 [2] 53 c1 [2] 14 c3 [2] 53 d2 [2] 1d de [2] 11 d4 [2] 06 df [2] 1d 91 [2] 20 }

  condition:
    any of them
}