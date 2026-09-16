rule TTP_XOR_MULT_DOSStub_7fd4 {
  strings:
    $key_7fd4 = { 2b bc [2] 5f a4 [2] 18 a6 [2] 5f b7 [2] 11 bb [2] 1d b1 [2] 0a ba [2] 11 f4 [2] 2c }

  condition:
    any of them
}