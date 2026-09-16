rule TTP_XOR_MULT_DOSStub_b5c1 {
  strings:
    $key_b5c1 = { e1 a9 [2] 95 b1 [2] d2 b3 [2] 95 a2 [2] db ae [2] d7 a4 [2] c0 af [2] db e1 [2] e6 }

  condition:
    any of them
}