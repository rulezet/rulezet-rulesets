rule TTP_XOR_MULT_DOSStub_b1d6 {
  strings:
    $key_b1d6 = { e5 be [2] 91 a6 [2] d6 a4 [2] 91 b5 [2] df b9 [2] d3 b3 [2] c4 b8 [2] df f6 [2] e2 }

  condition:
    any of them
}