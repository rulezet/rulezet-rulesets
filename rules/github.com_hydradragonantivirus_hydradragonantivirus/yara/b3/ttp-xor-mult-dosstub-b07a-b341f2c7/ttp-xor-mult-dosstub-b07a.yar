rule TTP_XOR_MULT_DOSStub_b07a {
  strings:
    $key_b07a = { e4 12 [2] 90 0a [2] d7 08 [2] 90 19 [2] de 15 [2] d2 1f [2] c5 14 [2] de 5a [2] e3 }

  condition:
    any of them
}