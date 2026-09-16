rule TTP_XOR_MULT_DOSStub_56c3 {
  strings:
    $key_56c3 = { 02 ab [2] 76 b3 [2] 31 b1 [2] 76 a0 [2] 38 ac [2] 34 a6 [2] 23 ad [2] 38 e3 [2] 05 }

  condition:
    any of them
}