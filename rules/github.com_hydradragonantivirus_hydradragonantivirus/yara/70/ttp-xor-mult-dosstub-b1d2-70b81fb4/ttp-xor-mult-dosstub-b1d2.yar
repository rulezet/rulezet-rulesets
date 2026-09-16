rule TTP_XOR_MULT_DOSStub_b1d2 {
  strings:
    $key_b1d2 = { e5 ba [2] 91 a2 [2] d6 a0 [2] 91 b1 [2] df bd [2] d3 b7 [2] c4 bc [2] df f2 [2] e2 }

  condition:
    any of them
}