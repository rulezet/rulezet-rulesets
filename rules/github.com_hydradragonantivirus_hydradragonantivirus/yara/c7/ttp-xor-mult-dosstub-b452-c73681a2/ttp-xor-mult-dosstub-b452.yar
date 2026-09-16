rule TTP_XOR_MULT_DOSStub_b452 {
  strings:
    $key_b452 = { e0 3a [2] 94 22 [2] d3 20 [2] 94 31 [2] da 3d [2] d6 37 [2] c1 3c [2] da 72 [2] e7 }

  condition:
    any of them
}