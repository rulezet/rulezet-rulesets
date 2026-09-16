rule TTP_XOR_MULT_DOSStub_b39a {
  strings:
    $key_b39a = { e7 f2 [2] 93 ea [2] d4 e8 [2] 93 f9 [2] dd f5 [2] d1 ff [2] c6 f4 [2] dd ba [2] e0 }

  condition:
    any of them
}