rule TTP_XOR_MULT_DOSStub_17c3 {
  strings:
    $key_17c3 = { 43 ab [2] 37 b3 [2] 70 b1 [2] 37 a0 [2] 79 ac [2] 75 a6 [2] 62 ad [2] 79 e3 [2] 44 }

  condition:
    any of them
}