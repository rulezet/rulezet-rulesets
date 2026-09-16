rule TTP_XOR_MULT_DOSStub_47c3 {
  strings:
    $key_47c3 = { 13 ab [2] 67 b3 [2] 20 b1 [2] 67 a0 [2] 29 ac [2] 25 a6 [2] 32 ad [2] 29 e3 [2] 14 }

  condition:
    any of them
}