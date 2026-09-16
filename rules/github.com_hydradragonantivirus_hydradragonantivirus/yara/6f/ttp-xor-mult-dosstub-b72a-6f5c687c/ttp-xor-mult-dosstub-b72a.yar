rule TTP_XOR_MULT_DOSStub_b72a {
  strings:
    $key_b72a = { e3 42 [2] 97 5a [2] d0 58 [2] 97 49 [2] d9 45 [2] d5 4f [2] c2 44 [2] d9 0a [2] e4 }

  condition:
    any of them
}