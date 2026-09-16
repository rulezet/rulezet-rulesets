rule TTP_XOR_MULT_DOSStub_b7b1 {
  strings:
    $key_b7b1 = { e3 d9 [2] 97 c1 [2] d0 c3 [2] 97 d2 [2] d9 de [2] d5 d4 [2] c2 df [2] d9 91 [2] e4 }

  condition:
    any of them
}