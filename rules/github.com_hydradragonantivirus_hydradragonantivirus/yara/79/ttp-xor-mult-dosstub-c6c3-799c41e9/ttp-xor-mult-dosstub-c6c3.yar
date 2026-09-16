rule TTP_XOR_MULT_DOSStub_c6c3 {
  strings:
    $key_c6c3 = { 92 ab [2] e6 b3 [2] a1 b1 [2] e6 a0 [2] a8 ac [2] a4 a6 [2] b3 ad [2] a8 e3 [2] 95 }

  condition:
    any of them
}