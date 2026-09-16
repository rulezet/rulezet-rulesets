rule TTP_XOR_MULT_DOSStub_b044 {
  strings:
    $key_b044 = { e4 2c [2] 90 34 [2] d7 36 [2] 90 27 [2] de 2b [2] d2 21 [2] c5 2a [2] de 64 [2] e3 }

  condition:
    any of them
}