rule TTP_XOR_MULT_DOSStub_b760 {
  strings:
    $key_b760 = { e3 08 [2] 97 10 [2] d0 12 [2] 97 03 [2] d9 0f [2] d5 05 [2] c2 0e [2] d9 40 [2] e4 }

  condition:
    any of them
}