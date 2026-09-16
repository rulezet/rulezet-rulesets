rule TTP_XOR_MULT_DOSStub_b432 {
  strings:
    $key_b432 = { e0 5a [2] 94 42 [2] d3 40 [2] 94 51 [2] da 5d [2] d6 57 [2] c1 5c [2] da 12 [2] e7 }

  condition:
    any of them
}