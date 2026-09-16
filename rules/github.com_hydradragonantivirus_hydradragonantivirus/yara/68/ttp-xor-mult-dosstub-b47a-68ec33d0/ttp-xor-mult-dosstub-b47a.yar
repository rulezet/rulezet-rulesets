rule TTP_XOR_MULT_DOSStub_b47a {
  strings:
    $key_b47a = { e0 12 [2] 94 0a [2] d3 08 [2] 94 19 [2] da 15 [2] d6 1f [2] c1 14 [2] da 5a [2] e7 }

  condition:
    any of them
}