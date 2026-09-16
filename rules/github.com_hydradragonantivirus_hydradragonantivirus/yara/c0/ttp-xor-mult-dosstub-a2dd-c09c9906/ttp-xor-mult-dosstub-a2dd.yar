rule TTP_XOR_MULT_DOSStub_a2dd {
  strings:
    $key_a2dd = { f6 b5 [2] 82 ad [2] c5 af [2] 82 be [2] cc b2 [2] c0 b8 [2] d7 b3 [2] cc fd [2] f1 }

  condition:
    any of them
}