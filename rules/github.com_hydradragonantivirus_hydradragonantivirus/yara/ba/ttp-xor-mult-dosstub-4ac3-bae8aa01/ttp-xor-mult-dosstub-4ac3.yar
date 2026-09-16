rule TTP_XOR_MULT_DOSStub_4ac3 {
  strings:
    $key_4ac3 = { 1e ab [2] 6a b3 [2] 2d b1 [2] 6a a0 [2] 24 ac [2] 28 a6 [2] 3f ad [2] 24 e3 [2] 19 }

  condition:
    any of them
}