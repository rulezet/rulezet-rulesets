rule TTP_XOR_MULT_DOSStub_b44a {
  strings:
    $key_b44a = { e0 22 [2] 94 3a [2] d3 38 [2] 94 29 [2] da 25 [2] d6 2f [2] c1 24 [2] da 6a [2] e7 }

  condition:
    any of them
}