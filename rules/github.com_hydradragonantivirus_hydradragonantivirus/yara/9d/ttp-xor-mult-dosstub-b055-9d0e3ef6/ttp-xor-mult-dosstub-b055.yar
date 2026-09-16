rule TTP_XOR_MULT_DOSStub_b055 {
  strings:
    $key_b055 = { e4 3d [2] 90 25 [2] d7 27 [2] 90 36 [2] de 3a [2] d2 30 [2] c5 3b [2] de 75 [2] e3 }

  condition:
    any of them
}