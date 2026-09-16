rule TTP_XOR_MULT_DOSStub_b435 {
  strings:
    $key_b435 = { e0 5d [2] 94 45 [2] d3 47 [2] 94 56 [2] da 5a [2] d6 50 [2] c1 5b [2] da 15 [2] e7 }

  condition:
    any of them
}