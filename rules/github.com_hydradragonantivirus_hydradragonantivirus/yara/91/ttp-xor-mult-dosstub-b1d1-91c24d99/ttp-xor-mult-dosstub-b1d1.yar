rule TTP_XOR_MULT_DOSStub_b1d1 {
  strings:
    $key_b1d1 = { e5 b9 [2] 91 a1 [2] d6 a3 [2] 91 b2 [2] df be [2] d3 b4 [2] c4 bf [2] df f1 [2] e2 }

  condition:
    any of them
}