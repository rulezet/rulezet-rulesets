rule TTP_XOR_MULT_DOSStub_3dc8 {
  strings:
    $key_3dc8 = { 69 a0 [2] 1d b8 [2] 5a ba [2] 1d ab [2] 53 a7 [2] 5f ad [2] 48 a6 [2] 53 e8 [2] 6e }

  condition:
    any of them
}