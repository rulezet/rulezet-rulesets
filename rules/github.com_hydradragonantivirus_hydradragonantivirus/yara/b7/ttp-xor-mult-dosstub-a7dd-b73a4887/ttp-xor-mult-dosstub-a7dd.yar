rule TTP_XOR_MULT_DOSStub_a7dd {
  strings:
    $key_a7dd = { f3 b5 [2] 87 ad [2] c0 af [2] 87 be [2] c9 b2 [2] c5 b8 [2] d2 b3 [2] c9 fd [2] f4 }

  condition:
    any of them
}