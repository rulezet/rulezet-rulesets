rule TTP_XOR_MULT_DOSStub_b417 {
  strings:
    $key_b417 = { e0 7f [2] 94 67 [2] d3 65 [2] 94 74 [2] da 78 [2] d6 72 [2] c1 79 [2] da 37 [2] e7 }

  condition:
    any of them
}