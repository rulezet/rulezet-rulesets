rule TTP_XOR_MULT_DOSStub_b446 {
  strings:
    $key_b446 = { e0 2e [2] 94 36 [2] d3 34 [2] 94 25 [2] da 29 [2] d6 23 [2] c1 28 [2] da 66 [2] e7 }

  condition:
    any of them
}