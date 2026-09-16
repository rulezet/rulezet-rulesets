rule TTP_XOR_MULT_DOSStub_92c0 {
  strings:
    $key_92c0 = { c6 a8 [2] b2 b0 [2] f5 b2 [2] b2 a3 [2] fc af [2] f0 a5 [2] e7 ae [2] fc e0 [2] c1 }

  condition:
    any of them
}