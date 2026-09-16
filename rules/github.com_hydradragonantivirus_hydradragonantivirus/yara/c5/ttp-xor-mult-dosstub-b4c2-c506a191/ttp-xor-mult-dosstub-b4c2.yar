rule TTP_XOR_MULT_DOSStub_b4c2 {
  strings:
    $key_b4c2 = { e0 aa [2] 94 b2 [2] d3 b0 [2] 94 a1 [2] da ad [2] d6 a7 [2] c1 ac [2] da e2 [2] e7 }

  condition:
    any of them
}