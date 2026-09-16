rule TTP_XOR_MULT_DOSStub_c7c3 {
  strings:
    $key_c7c3 = { 93 ab [2] e7 b3 [2] a0 b1 [2] e7 a0 [2] a9 ac [2] a5 a6 [2] b2 ad [2] a9 e3 [2] 94 }

  condition:
    any of them
}