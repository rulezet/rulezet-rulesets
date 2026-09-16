rule TTP_XOR_MULT_DOSStub_b45b {
  strings:
    $key_b45b = { e0 33 [2] 94 2b [2] d3 29 [2] 94 38 [2] da 34 [2] d6 3e [2] c1 35 [2] da 7b [2] e7 }

  condition:
    any of them
}