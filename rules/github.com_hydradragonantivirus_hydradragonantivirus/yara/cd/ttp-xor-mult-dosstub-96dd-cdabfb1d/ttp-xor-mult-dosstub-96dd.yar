rule TTP_XOR_MULT_DOSStub_96dd {
  strings:
    $key_96dd = { c2 b5 [2] b6 ad [2] f1 af [2] b6 be [2] f8 b2 [2] f4 b8 [2] e3 b3 [2] f8 fd [2] c5 }

  condition:
    any of them
}