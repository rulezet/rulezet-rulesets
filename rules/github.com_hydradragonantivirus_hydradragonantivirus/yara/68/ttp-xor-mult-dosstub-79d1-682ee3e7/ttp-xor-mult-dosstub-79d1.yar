rule TTP_XOR_MULT_DOSStub_79d1 {
  strings:
    $key_79d1 = { 2d b9 [2] 59 a1 [2] 1e a3 [2] 59 b2 [2] 17 be [2] 1b b4 [2] 0c bf [2] 17 f1 [2] 2a }

  condition:
    any of them
}