rule TTP_XOR_MULT_DOSStub_27c3 {
  strings:
    $key_27c3 = { 73 ab [2] 07 b3 [2] 40 b1 [2] 07 a0 [2] 49 ac [2] 45 a6 [2] 52 ad [2] 49 e3 [2] 74 }

  condition:
    any of them
}