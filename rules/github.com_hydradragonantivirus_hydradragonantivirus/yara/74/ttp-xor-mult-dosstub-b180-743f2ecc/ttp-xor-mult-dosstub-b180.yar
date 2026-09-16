rule TTP_XOR_MULT_DOSStub_b180 {
  strings:
    $key_b180 = { e5 e8 [2] 91 f0 [2] d6 f2 [2] 91 e3 [2] df ef [2] d3 e5 [2] c4 ee [2] df a0 [2] e2 }

  condition:
    any of them
}