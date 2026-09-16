rule TTP_XOR_MULT_DOSStub_b427 {
  strings:
    $key_b427 = { e0 4f [2] 94 57 [2] d3 55 [2] 94 44 [2] da 48 [2] d6 42 [2] c1 49 [2] da 07 [2] e7 }

  condition:
    any of them
}