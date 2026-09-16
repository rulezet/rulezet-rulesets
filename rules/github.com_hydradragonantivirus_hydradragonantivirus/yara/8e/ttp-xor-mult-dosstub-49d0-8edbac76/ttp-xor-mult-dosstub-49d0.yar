rule TTP_XOR_MULT_DOSStub_49d0 {
  strings:
    $key_49d0 = { 1d b8 [2] 69 a0 [2] 2e a2 [2] 69 b3 [2] 27 bf [2] 2b b5 [2] 3c be [2] 27 f0 [2] 1a }

  condition:
    any of them
}