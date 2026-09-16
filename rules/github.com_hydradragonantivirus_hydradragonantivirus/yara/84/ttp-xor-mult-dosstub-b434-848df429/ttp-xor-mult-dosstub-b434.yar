rule TTP_XOR_MULT_DOSStub_b434 {
  strings:
    $key_b434 = { e0 5c [2] 94 44 [2] d3 46 [2] 94 57 [2] da 5b [2] d6 51 [2] c1 5a [2] da 14 [2] e7 }

  condition:
    any of them
}