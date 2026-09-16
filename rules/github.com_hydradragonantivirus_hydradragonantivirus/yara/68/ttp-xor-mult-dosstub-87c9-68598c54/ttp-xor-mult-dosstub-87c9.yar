rule TTP_XOR_MULT_DOSStub_87c9 {
  strings:
    $key_87c9 = { d3 a1 [2] a7 b9 [2] e0 bb [2] a7 aa [2] e9 a6 [2] e5 ac [2] f2 a7 [2] e9 e9 [2] d4 }

  condition:
    any of them
}