rule TTP_XOR_MULT_DOSStub_b03a {
  strings:
    $key_b03a = { e4 52 [2] 90 4a [2] d7 48 [2] 90 59 [2] de 55 [2] d2 5f [2] c5 54 [2] de 1a [2] e3 }

  condition:
    any of them
}