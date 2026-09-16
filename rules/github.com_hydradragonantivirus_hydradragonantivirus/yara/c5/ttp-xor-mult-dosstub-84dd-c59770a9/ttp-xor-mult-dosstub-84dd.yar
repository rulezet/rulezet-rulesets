rule TTP_XOR_MULT_DOSStub_84dd {
  strings:
    $key_84dd = { d0 b5 [2] a4 ad [2] e3 af [2] a4 be [2] ea b2 [2] e6 b8 [2] f1 b3 [2] ea fd [2] d7 }

  condition:
    any of them
}