rule TTP_XOR_MULT_DOSStub_b70a {
  strings:
    $key_b70a = { e3 62 [2] 97 7a [2] d0 78 [2] 97 69 [2] d9 65 [2] d5 6f [2] c2 64 [2] d9 2a [2] e4 }

  condition:
    any of them
}