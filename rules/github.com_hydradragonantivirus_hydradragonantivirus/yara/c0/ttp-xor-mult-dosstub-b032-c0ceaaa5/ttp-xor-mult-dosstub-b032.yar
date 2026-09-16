rule TTP_XOR_MULT_DOSStub_b032 {
  strings:
    $key_b032 = { e4 5a [2] 90 42 [2] d7 40 [2] 90 51 [2] de 5d [2] d2 57 [2] c5 5c [2] de 12 [2] e3 }

  condition:
    any of them
}