rule TTP_XOR_MULT_DOSStub_18c3 {
  strings:
    $key_18c3 = { 4c ab [2] 38 b3 [2] 7f b1 [2] 38 a0 [2] 76 ac [2] 7a a6 [2] 6d ad [2] 76 e3 [2] 4b }

  condition:
    any of them
}