rule TTP_XOR_MULT_DOSStub_b0f6 {
  strings:
    $key_b0f6 = { e4 9e [2] 90 86 [2] d7 84 [2] 90 95 [2] de 99 [2] d2 93 [2] c5 98 [2] de d6 [2] e3 }

  condition:
    any of them
}