rule TTP_XOR_MULT_DOSStub_b5c7 {
  strings:
    $key_b5c7 = { e1 af [2] 95 b7 [2] d2 b5 [2] 95 a4 [2] db a8 [2] d7 a2 [2] c0 a9 [2] db e7 [2] e6 }

  condition:
    any of them
}