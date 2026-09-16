rule TTP_XOR_MULT_DOSStub_67c3 {
  strings:
    $key_67c3 = { 33 ab [2] 47 b3 [2] 00 b1 [2] 47 a0 [2] 09 ac [2] 05 a6 [2] 12 ad [2] 09 e3 [2] 34 }

  condition:
    any of them
}