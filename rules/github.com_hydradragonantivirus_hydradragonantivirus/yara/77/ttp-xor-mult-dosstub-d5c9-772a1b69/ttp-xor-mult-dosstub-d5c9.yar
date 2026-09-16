rule TTP_XOR_MULT_DOSStub_d5c9 {
  strings:
    $key_d5c9 = { 81 a1 [2] f5 b9 [2] b2 bb [2] f5 aa [2] bb a6 [2] b7 ac [2] a0 a7 [2] bb e9 [2] 86 }

  condition:
    any of them
}