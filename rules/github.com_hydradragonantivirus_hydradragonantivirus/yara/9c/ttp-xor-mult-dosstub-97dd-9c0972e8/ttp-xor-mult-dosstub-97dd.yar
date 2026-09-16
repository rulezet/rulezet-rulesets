rule TTP_XOR_MULT_DOSStub_97dd {
  strings:
    $key_97dd = { c3 b5 [2] b7 ad [2] f0 af [2] b7 be [2] f9 b2 [2] f5 b8 [2] e2 b3 [2] f9 fd [2] c4 }

  condition:
    any of them
}