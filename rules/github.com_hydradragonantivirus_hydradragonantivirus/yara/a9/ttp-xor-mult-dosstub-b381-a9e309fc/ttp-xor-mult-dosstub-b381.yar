rule TTP_XOR_MULT_DOSStub_b381 {
  strings:
    $key_b381 = { e7 e9 [2] 93 f1 [2] d4 f3 [2] 93 e2 [2] dd ee [2] d1 e4 [2] c6 ef [2] dd a1 [2] e0 }

  condition:
    any of them
}