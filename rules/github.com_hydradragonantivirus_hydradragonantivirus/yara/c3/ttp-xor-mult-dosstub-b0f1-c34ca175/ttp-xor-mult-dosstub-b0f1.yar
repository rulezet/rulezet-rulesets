rule TTP_XOR_MULT_DOSStub_b0f1 {
  strings:
    $key_b0f1 = { e4 99 [2] 90 81 [2] d7 83 [2] 90 92 [2] de 9e [2] d2 94 [2] c5 9f [2] de d1 [2] e3 }

  condition:
    any of them
}