rule TTP_XOR_MULT_DOSStub_92c5 {
  strings:
    $key_92c5 = { c6 ad [2] b2 b5 [2] f5 b7 [2] b2 a6 [2] fc aa [2] f0 a0 [2] e7 ab [2] fc e5 [2] c1 }

  condition:
    any of them
}