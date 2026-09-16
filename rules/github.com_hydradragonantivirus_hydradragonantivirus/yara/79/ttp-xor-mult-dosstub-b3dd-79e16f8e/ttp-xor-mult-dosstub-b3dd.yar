rule TTP_XOR_MULT_DOSStub_b3dd {
  strings:
    $key_b3dd = { e7 b5 [2] 93 ad [2] d4 af [2] 93 be [2] dd b2 [2] d1 b8 [2] c6 b3 [2] dd fd [2] e0 }

  condition:
    any of them
}