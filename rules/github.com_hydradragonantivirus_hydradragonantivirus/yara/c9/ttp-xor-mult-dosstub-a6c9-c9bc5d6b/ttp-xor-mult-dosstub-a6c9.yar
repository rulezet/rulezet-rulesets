rule TTP_XOR_MULT_DOSStub_a6c9 {
  strings:
    $key_a6c9 = { f2 a1 [2] 86 b9 [2] c1 bb [2] 86 aa [2] c8 a6 [2] c4 ac [2] d3 a7 [2] c8 e9 [2] f5 }

  condition:
    any of them
}