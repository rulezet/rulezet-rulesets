rule TTP_XOR_MULT_DOSStub_b046 {
  strings:
    $key_b046 = { e4 2e [2] 90 36 [2] d7 34 [2] 90 25 [2] de 29 [2] d2 23 [2] c5 28 [2] de 66 [2] e3 }

  condition:
    any of them
}