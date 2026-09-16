rule TTP_XOR_MULT_DOSStub_b042 {
  strings:
    $key_b042 = { e4 2a [2] 90 32 [2] d7 30 [2] 90 21 [2] de 2d [2] d2 27 [2] c5 2c [2] de 62 [2] e3 }

  condition:
    any of them
}