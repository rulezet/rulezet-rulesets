rule TTP_XOR_MULT_DOSStub_b40a {
  strings:
    $key_b40a = { e0 62 [2] 94 7a [2] d3 78 [2] 94 69 [2] da 65 [2] d6 6f [2] c1 64 [2] da 2a [2] e7 }

  condition:
    any of them
}