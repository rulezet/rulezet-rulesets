rule TTP_XOR_MULT_DOSStub_92d2 {
  strings:
    $key_92d2 = { c6 ba [2] b2 a2 [2] f5 a0 [2] b2 b1 [2] fc bd [2] f0 b7 [2] e7 bc [2] fc f2 [2] c1 }

  condition:
    any of them
}