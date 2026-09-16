rule TTP_XOR_MULT_DOSStub_78c3 {
  strings:
    $key_78c3 = { 2c ab [2] 58 b3 [2] 1f b1 [2] 58 a0 [2] 16 ac [2] 1a a6 [2] 0d ad [2] 16 e3 [2] 2b }

  condition:
    any of them
}