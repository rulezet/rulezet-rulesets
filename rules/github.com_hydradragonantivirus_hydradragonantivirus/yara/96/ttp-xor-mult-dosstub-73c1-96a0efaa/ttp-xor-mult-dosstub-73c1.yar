rule TTP_XOR_MULT_DOSStub_73c1 {
  strings:
    $key_73c1 = { 27 a9 [2] 53 b1 [2] 14 b3 [2] 53 a2 [2] 1d ae [2] 11 a4 [2] 06 af [2] 1d e1 [2] 20 }

  condition:
    any of them
}