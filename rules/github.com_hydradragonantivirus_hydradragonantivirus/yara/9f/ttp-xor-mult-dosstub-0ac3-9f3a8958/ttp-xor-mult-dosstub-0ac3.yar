rule TTP_XOR_MULT_DOSStub_0ac3 {
  strings:
    $key_0ac3 = { 5e ab [2] 2a b3 [2] 6d b1 [2] 2a a0 [2] 64 ac [2] 68 a6 [2] 7f ad [2] 64 e3 [2] 59 }

  condition:
    any of them
}