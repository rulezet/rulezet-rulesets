rule TTP_XOR_MULT_DOSStub_b01a {
  strings:
    $key_b01a = { e4 72 [2] 90 6a [2] d7 68 [2] 90 79 [2] de 75 [2] d2 7f [2] c5 74 [2] de 3a [2] e3 }

  condition:
    any of them
}