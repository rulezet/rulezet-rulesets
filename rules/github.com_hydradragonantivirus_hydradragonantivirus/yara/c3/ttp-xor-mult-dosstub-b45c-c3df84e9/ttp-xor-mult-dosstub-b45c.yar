rule TTP_XOR_MULT_DOSStub_b45c {
  strings:
    $key_b45c = { e0 34 [2] 94 2c [2] d3 2e [2] 94 3f [2] da 33 [2] d6 39 [2] c1 32 [2] da 7c [2] e7 }

  condition:
    any of them
}