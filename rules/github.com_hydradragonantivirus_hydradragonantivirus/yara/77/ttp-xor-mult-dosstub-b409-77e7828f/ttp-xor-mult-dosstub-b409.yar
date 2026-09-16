rule TTP_XOR_MULT_DOSStub_b409 {
  strings:
    $key_b409 = { e0 61 [2] 94 79 [2] d3 7b [2] 94 6a [2] da 66 [2] d6 6c [2] c1 67 [2] da 29 [2] e7 }

  condition:
    any of them
}