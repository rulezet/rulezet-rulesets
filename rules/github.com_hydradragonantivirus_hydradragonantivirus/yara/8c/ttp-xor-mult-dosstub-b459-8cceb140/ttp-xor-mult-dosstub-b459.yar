rule TTP_XOR_MULT_DOSStub_b459 {
  strings:
    $key_b459 = { e0 31 [2] 94 29 [2] d3 2b [2] 94 3a [2] da 36 [2] d6 3c [2] c1 37 [2] da 79 [2] e7 }

  condition:
    any of them
}