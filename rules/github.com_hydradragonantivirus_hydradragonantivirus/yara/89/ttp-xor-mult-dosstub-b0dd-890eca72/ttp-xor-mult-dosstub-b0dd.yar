rule TTP_XOR_MULT_DOSStub_b0dd {
  strings:
    $key_b0dd = { e4 b5 [2] 90 ad [2] d7 af [2] 90 be [2] de b2 [2] d2 b8 [2] c5 b3 [2] de fd [2] e3 }

  condition:
    any of them
}