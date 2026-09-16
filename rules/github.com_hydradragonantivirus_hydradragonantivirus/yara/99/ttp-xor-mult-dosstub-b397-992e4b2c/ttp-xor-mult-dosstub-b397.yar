rule TTP_XOR_MULT_DOSStub_b397 {
  strings:
    $key_b397 = { e7 ff [2] 93 e7 [2] d4 e5 [2] 93 f4 [2] dd f8 [2] d1 f2 [2] c6 f9 [2] dd b7 [2] e0 }

  condition:
    any of them
}