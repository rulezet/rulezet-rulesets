rule TTP_XOR_MULT_DOSStub_92c9 {
  strings:
    $key_92c9 = { c6 a1 [2] b2 b9 [2] f5 bb [2] b2 aa [2] fc a6 [2] f0 ac [2] e7 a7 [2] fc e9 [2] c1 }

  condition:
    any of them
}