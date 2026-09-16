rule TTP_XOR_MULT_DOSStub_b479 {
  strings:
    $key_b479 = { e0 11 [2] 94 09 [2] d3 0b [2] 94 1a [2] da 16 [2] d6 1c [2] c1 17 [2] da 59 [2] e7 }

  condition:
    any of them
}