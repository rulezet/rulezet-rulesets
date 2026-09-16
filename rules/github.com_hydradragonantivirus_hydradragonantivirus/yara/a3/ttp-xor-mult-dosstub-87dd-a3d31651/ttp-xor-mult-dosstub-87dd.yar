rule TTP_XOR_MULT_DOSStub_87dd {
  strings:
    $key_87dd = { d3 b5 [2] a7 ad [2] e0 af [2] a7 be [2] e9 b2 [2] e5 b8 [2] f2 b3 [2] e9 fd [2] d4 }

  condition:
    any of them
}