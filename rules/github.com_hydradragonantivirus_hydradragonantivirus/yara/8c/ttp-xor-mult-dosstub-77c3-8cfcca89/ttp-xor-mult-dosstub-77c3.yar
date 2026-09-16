rule TTP_XOR_MULT_DOSStub_77c3 {
  strings:
    $key_77c3 = { 23 ab [2] 57 b3 [2] 10 b1 [2] 57 a0 [2] 19 ac [2] 15 a6 [2] 02 ad [2] 19 e3 [2] 24 }

  condition:
    any of them
}