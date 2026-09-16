rule TTP_XOR_MULT_DOSStub_b47c {
  strings:
    $key_b47c = { e0 14 [2] 94 0c [2] d3 0e [2] 94 1f [2] da 13 [2] d6 19 [2] c1 12 [2] da 5c [2] e7 }

  condition:
    any of them
}