rule TTP_XOR_MULT_DOSStub_b6dd {
  strings:
    $key_b6dd = { e2 b5 [2] 96 ad [2] d1 af [2] 96 be [2] d8 b2 [2] d4 b8 [2] c3 b3 [2] d8 fd [2] e5 }

  condition:
    any of them
}