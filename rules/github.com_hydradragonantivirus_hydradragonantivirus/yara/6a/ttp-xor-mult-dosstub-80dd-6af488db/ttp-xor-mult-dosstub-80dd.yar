rule TTP_XOR_MULT_DOSStub_80dd {
  strings:
    $key_80dd = { d4 b5 [2] a0 ad [2] e7 af [2] a0 be [2] ee b2 [2] e2 b8 [2] f5 b3 [2] ee fd [2] d3 }

  condition:
    any of them
}