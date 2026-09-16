rule TTP_XOR_MULT_DOSStub_a4dd {
  strings:
    $key_a4dd = { f0 b5 [2] 84 ad [2] c3 af [2] 84 be [2] ca b2 [2] c6 b8 [2] d1 b3 [2] ca fd [2] f7 }

  condition:
    any of them
}