rule TTP_XOR_MULT_DOSStub_b387 {
  strings:
    $key_b387 = { e7 ef [2] 93 f7 [2] d4 f5 [2] 93 e4 [2] dd e8 [2] d1 e2 [2] c6 e9 [2] dd a7 [2] e0 }

  condition:
    any of them
}