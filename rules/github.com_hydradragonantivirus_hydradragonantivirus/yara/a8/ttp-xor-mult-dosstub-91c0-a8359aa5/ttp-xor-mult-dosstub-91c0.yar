rule TTP_XOR_MULT_DOSStub_91c0 {
  strings:
    $key_91c0 = { c5 a8 [2] b1 b0 [2] f6 b2 [2] b1 a3 [2] ff af [2] f3 a5 [2] e4 ae [2] ff e0 [2] c2 }

  condition:
    any of them
}