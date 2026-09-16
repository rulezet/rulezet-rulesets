rule TTP_XOR_MULT_DOSStub_b052 {
  strings:
    $key_b052 = { e4 3a [2] 90 22 [2] d7 20 [2] 90 31 [2] de 3d [2] d2 37 [2] c5 3c [2] de 72 [2] e3 }

  condition:
    any of them
}