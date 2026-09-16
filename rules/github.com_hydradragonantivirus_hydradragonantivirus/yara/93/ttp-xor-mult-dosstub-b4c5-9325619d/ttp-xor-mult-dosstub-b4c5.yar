rule TTP_XOR_MULT_DOSStub_b4c5 {
  strings:
    $key_b4c5 = { e0 ad [2] 94 b5 [2] d3 b7 [2] 94 a6 [2] da aa [2] d6 a0 [2] c1 ab [2] da e5 [2] e7 }

  condition:
    any of them
}