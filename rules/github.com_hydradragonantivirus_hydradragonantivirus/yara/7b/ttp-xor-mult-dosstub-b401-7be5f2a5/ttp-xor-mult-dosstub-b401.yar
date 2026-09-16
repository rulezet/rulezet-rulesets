rule TTP_XOR_MULT_DOSStub_b401 {
  strings:
    $key_b401 = { e0 69 [2] 94 71 [2] d3 73 [2] 94 62 [2] da 6e [2] d6 64 [2] c1 6f [2] da 21 [2] e7 }

  condition:
    any of them
}