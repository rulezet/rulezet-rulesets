rule TTP_XOR_MULT_DOSStub_a7c9 {
  strings:
    $key_a7c9 = { f3 a1 [2] 87 b9 [2] c0 bb [2] 87 aa [2] c9 a6 [2] c5 ac [2] d2 a7 [2] c9 e9 [2] f4 }

  condition:
    any of them
}