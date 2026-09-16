rule TTP_XOR_MULT_DOSStub_b5d6 {
  strings:
    $key_b5d6 = { e1 be [2] 95 a6 [2] d2 a4 [2] 95 b5 [2] db b9 [2] d7 b3 [2] c0 b8 [2] db f6 [2] e6 }

  condition:
    any of them
}