rule TTP_XOR_MULT_DOSStub_b450 {
  strings:
    $key_b450 = { e0 38 [2] 94 20 [2] d3 22 [2] 94 33 [2] da 3f [2] d6 35 [2] c1 3e [2] da 70 [2] e7 }

  condition:
    any of them
}