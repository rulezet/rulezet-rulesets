rule TTP_XOR_MULT_DOSStub_b437 {
  strings:
    $key_b437 = { e0 5f [2] 94 47 [2] d3 45 [2] 94 54 [2] da 58 [2] d6 52 [2] c1 59 [2] da 17 [2] e7 }

  condition:
    any of them
}