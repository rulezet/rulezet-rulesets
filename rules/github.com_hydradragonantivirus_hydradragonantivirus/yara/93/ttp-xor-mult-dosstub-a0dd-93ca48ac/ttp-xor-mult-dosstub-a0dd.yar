rule TTP_XOR_MULT_DOSStub_a0dd {
  strings:
    $key_a0dd = { f4 b5 [2] 80 ad [2] c7 af [2] 80 be [2] ce b2 [2] c2 b8 [2] d5 b3 [2] ce fd [2] f3 }

  condition:
    any of them
}