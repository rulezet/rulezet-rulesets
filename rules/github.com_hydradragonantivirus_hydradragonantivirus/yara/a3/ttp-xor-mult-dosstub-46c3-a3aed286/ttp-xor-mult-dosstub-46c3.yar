rule TTP_XOR_MULT_DOSStub_46c3 {
  strings:
    $key_46c3 = { 12 ab [2] 66 b3 [2] 21 b1 [2] 66 a0 [2] 28 ac [2] 24 a6 [2] 33 ad [2] 28 e3 [2] 15 }

  condition:
    any of them
}