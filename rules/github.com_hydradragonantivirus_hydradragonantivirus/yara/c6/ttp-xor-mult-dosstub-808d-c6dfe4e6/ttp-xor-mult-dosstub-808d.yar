rule TTP_XOR_MULT_DOSStub_808d {
  strings:
    $key_808d = { d4 e5 [2] a0 fd [2] e7 ff [2] a0 ee [2] ee e2 [2] e2 e8 [2] f5 e3 [2] ee ad [2] d3 }

  condition:
    any of them
}