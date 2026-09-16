rule TTP_XOR_MULT_DOSStub_b414 {
  strings:
    $key_b414 = { e0 7c [2] 94 64 [2] d3 66 [2] 94 77 [2] da 7b [2] d6 71 [2] c1 7a [2] da 34 [2] e7 }

  condition:
    any of them
}