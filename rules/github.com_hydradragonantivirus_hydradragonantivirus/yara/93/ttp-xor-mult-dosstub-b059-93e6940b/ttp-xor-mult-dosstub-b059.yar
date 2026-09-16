rule TTP_XOR_MULT_DOSStub_b059 {
  strings:
    $key_b059 = { e4 31 [2] 90 29 [2] d7 2b [2] 90 3a [2] de 36 [2] d2 3c [2] c5 37 [2] de 79 [2] e3 }

  condition:
    any of them
}