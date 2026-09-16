rule TTP_XOR_MULT_DOSStub_73d4 {
  strings:
    $key_73d4 = { 27 bc [2] 53 a4 [2] 14 a6 [2] 53 b7 [2] 1d bb [2] 11 b1 [2] 06 ba [2] 1d f4 [2] 20 }

  condition:
    any of them
}