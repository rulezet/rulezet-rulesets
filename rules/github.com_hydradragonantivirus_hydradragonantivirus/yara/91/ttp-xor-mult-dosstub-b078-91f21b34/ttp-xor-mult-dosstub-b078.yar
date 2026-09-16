rule TTP_XOR_MULT_DOSStub_b078 {
  strings:
    $key_b078 = { e4 10 [2] 90 08 [2] d7 0a [2] 90 1b [2] de 17 [2] d2 1d [2] c5 16 [2] de 58 [2] e3 }

  condition:
    any of them
}