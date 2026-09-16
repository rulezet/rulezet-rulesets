rule TTP_XOR_MULT_DOSStub_b050 {
  strings:
    $key_b050 = { e4 38 [2] 90 20 [2] d7 22 [2] 90 33 [2] de 3f [2] d2 35 [2] c5 3e [2] de 70 [2] e3 }

  condition:
    any of them
}