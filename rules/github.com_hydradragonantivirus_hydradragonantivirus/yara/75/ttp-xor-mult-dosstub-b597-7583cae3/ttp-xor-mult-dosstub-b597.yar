rule TTP_XOR_MULT_DOSStub_b597 {
  strings:
    $key_b597 = { e1 ff [2] 95 e7 [2] d2 e5 [2] 95 f4 [2] db f8 [2] d7 f2 [2] c0 f9 [2] db b7 [2] e6 }

  condition:
    any of them
}