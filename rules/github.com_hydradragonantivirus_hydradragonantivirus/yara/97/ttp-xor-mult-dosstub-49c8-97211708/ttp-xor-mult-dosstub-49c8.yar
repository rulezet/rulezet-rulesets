rule TTP_XOR_MULT_DOSStub_49c8 {
  strings:
    $key_49c8 = { 1d a0 [2] 69 b8 [2] 2e ba [2] 69 ab [2] 27 a7 [2] 2b ad [2] 3c a6 [2] 27 e8 [2] 1a }

  condition:
    any of them
}