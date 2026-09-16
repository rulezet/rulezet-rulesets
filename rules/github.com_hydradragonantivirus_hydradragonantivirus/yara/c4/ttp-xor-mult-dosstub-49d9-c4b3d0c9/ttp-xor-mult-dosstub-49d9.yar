rule TTP_XOR_MULT_DOSStub_49d9 {
  strings:
    $key_49d9 = { 1d b1 [2] 69 a9 [2] 2e ab [2] 69 ba [2] 27 b6 [2] 2b bc [2] 3c b7 [2] 27 f9 [2] 1a }

  condition:
    any of them
}