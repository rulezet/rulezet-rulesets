rule TTP_XOR_MULT_DOSStub_a5dd {
  strings:
    $key_a5dd = { f1 b5 [2] 85 ad [2] c2 af [2] 85 be [2] cb b2 [2] c7 b8 [2] d0 b3 [2] cb fd [2] f6 }

  condition:
    any of them
}