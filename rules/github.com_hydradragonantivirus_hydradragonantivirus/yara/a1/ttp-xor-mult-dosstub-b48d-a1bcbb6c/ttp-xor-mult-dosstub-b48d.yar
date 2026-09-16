rule TTP_XOR_MULT_DOSStub_b48d {
  strings:
    $key_b48d = { e0 e5 [2] 94 fd [2] d3 ff [2] 94 ee [2] da e2 [2] d6 e8 [2] c1 e3 [2] da ad [2] e7 }

  condition:
    any of them
}