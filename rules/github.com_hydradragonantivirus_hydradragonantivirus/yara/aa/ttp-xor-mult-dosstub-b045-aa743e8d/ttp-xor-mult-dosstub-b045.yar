rule TTP_XOR_MULT_DOSStub_b045 {
  strings:
    $key_b045 = { e4 2d [2] 90 35 [2] d7 37 [2] 90 26 [2] de 2a [2] d2 20 [2] c5 2b [2] de 65 [2] e3 }

  condition:
    any of them
}