rule TTP_XOR_MULT_DOSStub_73c7 {
  strings:
    $key_73c7 = { 27 af [2] 53 b7 [2] 14 b5 [2] 53 a4 [2] 1d a8 [2] 11 a2 [2] 06 a9 [2] 1d e7 [2] 20 }

  condition:
    any of them
}