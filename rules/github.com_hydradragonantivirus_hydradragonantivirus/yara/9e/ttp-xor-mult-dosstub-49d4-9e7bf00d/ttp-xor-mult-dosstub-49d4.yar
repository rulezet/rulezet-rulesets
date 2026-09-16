rule TTP_XOR_MULT_DOSStub_49d4 {
  strings:
    $key_49d4 = { 1d bc [2] 69 a4 [2] 2e a6 [2] 69 b7 [2] 27 bb [2] 2b b1 [2] 3c ba [2] 27 f4 [2] 1a }

  condition:
    any of them
}