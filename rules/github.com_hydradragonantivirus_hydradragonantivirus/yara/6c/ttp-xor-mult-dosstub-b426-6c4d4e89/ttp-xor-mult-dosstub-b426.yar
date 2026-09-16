rule TTP_XOR_MULT_DOSStub_b426 {
  strings:
    $key_b426 = { e0 4e [2] 94 56 [2] d3 54 [2] 94 45 [2] da 49 [2] d6 43 [2] c1 48 [2] da 06 [2] e7 }

  condition:
    any of them
}