rule TTP_XOR_MULT_DOSStub_b4c4 {
  strings:
    $key_b4c4 = { e0 ac [2] 94 b4 [2] d3 b6 [2] 94 a7 [2] da ab [2] d6 a1 [2] c1 aa [2] da e4 [2] e7 }

  condition:
    any of them
}