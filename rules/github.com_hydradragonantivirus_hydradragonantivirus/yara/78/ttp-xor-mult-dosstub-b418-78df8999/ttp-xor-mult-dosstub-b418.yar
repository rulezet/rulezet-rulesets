rule TTP_XOR_MULT_DOSStub_b418 {
  strings:
    $key_b418 = { e0 70 [2] 94 68 [2] d3 6a [2] 94 7b [2] da 77 [2] d6 7d [2] c1 76 [2] da 38 [2] e7 }

  condition:
    any of them
}