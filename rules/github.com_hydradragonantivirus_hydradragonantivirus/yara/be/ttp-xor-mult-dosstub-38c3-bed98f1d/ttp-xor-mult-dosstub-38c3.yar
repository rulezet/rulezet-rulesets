rule TTP_XOR_MULT_DOSStub_38c3 {
  strings:
    $key_38c3 = { 6c ab [2] 18 b3 [2] 5f b1 [2] 18 a0 [2] 56 ac [2] 5a a6 [2] 4d ad [2] 56 e3 [2] 6b }

  condition:
    any of them
}