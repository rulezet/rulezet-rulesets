rule TTP_XOR_MULT_DOSStub_59c8 {
  strings:
    $key_59c8 = { 0d a0 [2] 79 b8 [2] 3e ba [2] 79 ab [2] 37 a7 [2] 3b ad [2] 2c a6 [2] 37 e8 [2] 0a }

  condition:
    any of them
}