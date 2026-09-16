rule TTP_XOR_MULT_DOSStub_b422 {
  strings:
    $key_b422 = { e0 4a [2] 94 52 [2] d3 50 [2] 94 41 [2] da 4d [2] d6 47 [2] c1 4c [2] da 02 [2] e7 }

  condition:
    any of them
}