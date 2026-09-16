rule TTP_XOR_MULT_DOSStub_87c3 {
  strings:
    $key_87c3 = { d3 ab [2] a7 b3 [2] e0 b1 [2] a7 a0 [2] e9 ac [2] e5 a6 [2] f2 ad [2] e9 e3 [2] d4 }

  condition:
    any of them
}