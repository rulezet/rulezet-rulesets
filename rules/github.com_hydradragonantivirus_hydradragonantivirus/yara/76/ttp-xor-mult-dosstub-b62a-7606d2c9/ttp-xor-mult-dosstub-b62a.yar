rule TTP_XOR_MULT_DOSStub_b62a {
  strings:
    $key_b62a = { e2 42 [2] 96 5a [2] d1 58 [2] 96 49 [2] d8 45 [2] d4 4f [2] c3 44 [2] d8 0a [2] e5 }

  condition:
    any of them
}