rule TTP_XOR_MULT_DOSStub_b0e0 {
  strings:
    $key_b0e0 = { e4 88 [2] 90 90 [2] d7 92 [2] 90 83 [2] de 8f [2] d2 85 [2] c5 8e [2] de c0 [2] e3 }

  condition:
    any of them
}