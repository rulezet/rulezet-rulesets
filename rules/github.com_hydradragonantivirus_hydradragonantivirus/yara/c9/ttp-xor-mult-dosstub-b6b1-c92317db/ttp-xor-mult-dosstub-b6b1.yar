rule TTP_XOR_MULT_DOSStub_b6b1 {
  strings:
    $key_b6b1 = { e2 d9 [2] 96 c1 [2] d1 c3 [2] 96 d2 [2] d8 de [2] d4 d4 [2] c3 df [2] d8 91 [2] e5 }

  condition:
    any of them
}