rule TTP_XOR_MULT_DOSStub_b0e1 {
  strings:
    $key_b0e1 = { e4 89 [2] 90 91 [2] d7 93 [2] 90 82 [2] de 8e [2] d2 84 [2] c5 8f [2] de c1 [2] e3 }

  condition:
    any of them
}