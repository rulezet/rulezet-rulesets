rule TTP_XOR_MULT_DOSStub_79d4 {
  strings:
    $key_79d4 = { 2d bc [2] 59 a4 [2] 1e a6 [2] 59 b7 [2] 17 bb [2] 1b b1 [2] 0c ba [2] 17 f4 [2] 2a }

  condition:
    any of them
}