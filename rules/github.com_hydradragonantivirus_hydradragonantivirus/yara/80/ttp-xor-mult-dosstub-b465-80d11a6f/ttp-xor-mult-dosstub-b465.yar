rule TTP_XOR_MULT_DOSStub_b465 {
  strings:
    $key_b465 = { e0 0d [2] 94 15 [2] d3 17 [2] 94 06 [2] da 0a [2] d6 00 [2] c1 0b [2] da 45 [2] e7 }

  condition:
    any of them
}