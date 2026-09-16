rule TTP_XOR_MULT_DOSStub_b02a {
  strings:
    $key_b02a = { e4 42 [2] 90 5a [2] d7 58 [2] 90 49 [2] de 45 [2] d2 4f [2] c5 44 [2] de 0a [2] e3 }

  condition:
    any of them
}