rule TTP_XOR_MULT_DOSStub_b1d9 {
  strings:
    $key_b1d9 = { e5 b1 [2] 91 a9 [2] d6 ab [2] 91 ba [2] df b6 [2] d3 bc [2] c4 b7 [2] df f9 [2] e2 }

  condition:
    any of them
}