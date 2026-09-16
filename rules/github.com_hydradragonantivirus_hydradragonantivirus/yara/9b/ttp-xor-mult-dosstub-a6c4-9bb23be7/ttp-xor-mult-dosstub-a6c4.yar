rule TTP_XOR_MULT_DOSStub_a6c4 {
  strings:
    $key_a6c4 = { f2 ac [2] 86 b4 [2] c1 b6 [2] 86 a7 [2] c8 ab [2] c4 a1 [2] d3 aa [2] c8 e4 [2] f5 }

  condition:
    any of them
}