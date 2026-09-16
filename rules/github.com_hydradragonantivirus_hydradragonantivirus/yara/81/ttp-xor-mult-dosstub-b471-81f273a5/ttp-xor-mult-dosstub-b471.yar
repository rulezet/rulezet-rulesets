rule TTP_XOR_MULT_DOSStub_b471 {
  strings:
    $key_b471 = { e0 19 [2] 94 01 [2] d3 03 [2] 94 12 [2] da 1e [2] d6 14 [2] c1 1f [2] da 51 [2] e7 }

  condition:
    any of them
}