rule TTP_XOR_MULT_DOSStub_b070 {
  strings:
    $key_b070 = { e4 18 [2] 90 00 [2] d7 02 [2] 90 13 [2] de 1f [2] d2 15 [2] c5 1e [2] de 50 [2] e3 }

  condition:
    any of them
}