rule TTP_XOR_MULT_DOSStub_a6c2 {
  strings:
    $key_a6c2 = { f2 aa [2] 86 b2 [2] c1 b0 [2] 86 a1 [2] c8 ad [2] c4 a7 [2] d3 ac [2] c8 e2 [2] f5 }

  condition:
    any of them
}