rule TTP_XOR_MULT_DOSStub_79d5 {
  strings:
    $key_79d5 = { 2d bd [2] 59 a5 [2] 1e a7 [2] 59 b6 [2] 17 ba [2] 1b b0 [2] 0c bb [2] 17 f5 [2] 2a }

  condition:
    any of them
}