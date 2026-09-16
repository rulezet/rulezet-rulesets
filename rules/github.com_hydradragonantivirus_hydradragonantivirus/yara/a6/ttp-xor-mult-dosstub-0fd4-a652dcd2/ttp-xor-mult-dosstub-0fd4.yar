rule TTP_XOR_MULT_DOSStub_0fd4 {
  strings:
    $key_0fd4 = { 5b bc [2] 2f a4 [2] 68 a6 [2] 2f b7 [2] 61 bb [2] 6d b1 [2] 7a ba [2] 61 f4 [2] 5c }

  condition:
    any of them
}