rule TTP_XOR_MULT_DOSStub_90c1 {
  strings:
    $key_90c1 = { c4 a9 [2] b0 b1 [2] f7 b3 [2] b0 a2 [2] fe ae [2] f2 a4 [2] e5 af [2] fe e1 [2] c3 }

  condition:
    any of them
}