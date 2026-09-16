rule TTP_XOR_MULT_DOSStub_b4dd {
  strings:
    $key_b4dd = { e0 b5 [2] 94 ad [2] d3 af [2] 94 be [2] da b2 [2] d6 b8 [2] c1 b3 [2] da fd [2] e7 }

  condition:
    any of them
}