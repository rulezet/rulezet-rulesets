rule TTP_XOR_MULT_DOSStub_b59a {
  strings:
    $key_b59a = { e1 f2 [2] 95 ea [2] d2 e8 [2] 95 f9 [2] db f5 [2] d7 ff [2] c0 f4 [2] db ba [2] e6 }

  condition:
    any of them
}