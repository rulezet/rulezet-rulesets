rule TTP_XOR_MULT_DOSStub_b0b1 {
  strings:
    $key_b0b1 = { e4 d9 [2] 90 c1 [2] d7 c3 [2] 90 d2 [2] de de [2] d2 d4 [2] c5 df [2] de 91 [2] e3 }

  condition:
    any of them
}