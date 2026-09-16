rule TTP_XOR_MULT_DOSStub_808f {
  strings:
    $key_808f = { d4 e7 [2] a0 ff [2] e7 fd [2] a0 ec [2] ee e0 [2] e2 ea [2] f5 e1 [2] ee af [2] d3 }

  condition:
    any of them
}