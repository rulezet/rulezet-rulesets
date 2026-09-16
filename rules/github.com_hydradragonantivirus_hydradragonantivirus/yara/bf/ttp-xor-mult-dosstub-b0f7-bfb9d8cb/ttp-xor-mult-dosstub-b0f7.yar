rule TTP_XOR_MULT_DOSStub_b0f7 {
  strings:
    $key_b0f7 = { e4 9f [2] 90 87 [2] d7 85 [2] 90 94 [2] de 98 [2] d2 92 [2] c5 99 [2] de d7 [2] e3 }

  condition:
    any of them
}