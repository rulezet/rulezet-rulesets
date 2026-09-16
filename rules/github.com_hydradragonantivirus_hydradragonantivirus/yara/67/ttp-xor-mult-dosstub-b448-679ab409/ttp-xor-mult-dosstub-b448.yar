rule TTP_XOR_MULT_DOSStub_b448 {
  strings:
    $key_b448 = { e0 20 [2] 94 38 [2] d3 3a [2] 94 2b [2] da 27 [2] d6 2d [2] c1 26 [2] da 68 [2] e7 }

  condition:
    any of them
}