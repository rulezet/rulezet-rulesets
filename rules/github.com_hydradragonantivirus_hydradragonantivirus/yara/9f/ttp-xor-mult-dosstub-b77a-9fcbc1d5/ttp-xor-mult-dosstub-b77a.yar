rule TTP_XOR_MULT_DOSStub_b77a {
  strings:
    $key_b77a = { e3 12 [2] 97 0a [2] d0 08 [2] 97 19 [2] d9 15 [2] d5 1f [2] c2 14 [2] d9 5a [2] e4 }

  condition:
    any of them
}