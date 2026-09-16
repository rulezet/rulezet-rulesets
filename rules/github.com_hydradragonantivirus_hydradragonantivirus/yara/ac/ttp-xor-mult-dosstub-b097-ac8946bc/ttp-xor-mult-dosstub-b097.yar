rule TTP_XOR_MULT_DOSStub_b097 {
  strings:
    $key_b097 = { e4 ff [2] 90 e7 [2] d7 e5 [2] 90 f4 [2] de f8 [2] d2 f2 [2] c5 f9 [2] de b7 [2] e3 }

  condition:
    any of them
}